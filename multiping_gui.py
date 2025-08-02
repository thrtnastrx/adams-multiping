import os
import sys
import socket
import subprocess
import platform
import re
import tkinter as tk
import tkinter.messagebox as messagebox
from tkinter import ttk
from multiping import MultiPing
import threading
import time
import ipaddress
from datetime import timedelta

if os.geteuid() != 0:
    tk.Tk().withdraw()
    messagebox.showerror("Permission Required", "Adam's Multi-Ping must be run with sudo (as root).\n\nPlease run:\n\nsudo python3 multiping_gui_24.py")
    sys.exit(1)

running = False
ping_thread = None
start_time = None
ping_stats = {}
sort_column = None
sort_reverse = False
active_hosts = set()
dns_cache = {}
mac_cache = {}
show_only_alive = False

INTERVAL_OPTIONS = {
    "0.1 sec": 0.1,
    "0.25 sec": 0.25,
    "0.5 sec": 0.5,
    "1 sec": 1,
    "2.5 sec": 2.5,
    "5 sec": 5,
    "10 sec": 10,
    "20 sec": 20,
    "30 sec": 30,
    "1 min": 60,
    "5 min": 300
}
interval_label_list = list(INTERVAL_OPTIONS.keys())

def expand_ips(input_str):
    ips = []
    for item in input_str.split(','):
        item = item.strip()
        if not item:
            continue
        if '-' in item and '/' not in item:
            try:
                start, end = item.split('-')
                start = start.strip()
                end = end.strip()
                base = start.rsplit('.', 1)[0]
                start_last = int(start.split('.')[-1])
                end_last = int(end.split('.')[-1]) if '.' not in end else int(end.split('.')[-1])
                for i in range(start_last, end_last + 1):
                    ips.append(f"{base}.{i}")
            except:
                pass
        else:
            try:
                net = ipaddress.ip_network(item, strict=False)
                ips.extend([str(ip) for ip in net.hosts()])
            except ValueError:
                ips.append(item)
    return list(set(ips))

def format_rtt(seconds):
    return f"{seconds * 1000:.2f} ms"

def get_loss_indicator(loss_pct):
    if loss_pct == 0.0:
        return "🟢 0.0%"
    elif loss_pct >= 100.0:
        return "🔴 100%"
    else:
        return f"🟡 {loss_pct:.1f}%"


def extract_number(value):
    try:
        import re
        # If it's an IP address, split and sort numerically
        if re.match(r'^\d+\.\d+\.\d+\.\d+$', value):
            return tuple(int(part) for part in value.split('.'))
        # Otherwise try to extract float
        value = ''.join(c for c in value if c.isdigit() or c == '.' or c == '-')
        return float(value)
    except:
        return float('inf')


def sort_treeview(col_index):
    global sort_column, sort_reverse
    sort_column = col_index
    sort_reverse = not sort_reverse
    apply_sort()

def apply_sort():
    if sort_column is None:
        return
    items = [(tree.set(k, sort_column), k) for k in tree.get_children("")]
    try:
        items.sort(key=lambda x: extract_number(x[0]), reverse=sort_reverse)
    except:
        items.sort(key=lambda x: x[0], reverse=sort_reverse)
    for index, (_, k) in enumerate(items):
        tree.move(k, "", index)

def resolve_dns(ip):
    if ip in dns_cache:
        return dns_cache[ip]
    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except socket.herror:
        hostname = "-"
    dns_cache[ip] = hostname
    return hostname

def resolve_mac(ip):
    if ip in mac_cache:
        return mac_cache[ip]
    system = platform.system()
    try:
        if system == "Linux":
            try:
                output = subprocess.check_output(["ip", "neigh"], text=True)
            except FileNotFoundError:
                output = subprocess.check_output(["arp", "-n"], text=True)
        elif system == "Darwin":
            output = subprocess.check_output(["arp", "-n", ip], text=True)
        else:
            return "-"
    except:
        return "-"
    for line in output.splitlines():
        if ip in line:
            match = re.search(r"(([0-9a-f]{1,2}[:-]){5}[0-9a-f]{1,2})", line, re.IGNORECASE)
            if match:
                mac_cache[ip] = match.group(0)
                return match.group(0)
    return "-"

def update_display(responses, no_responses):
    elapsed = timedelta(seconds=int(time.time() - start_time)) if start_time else "0:00:00"
    duration_label.config(text=f"Duration: {elapsed}")

    current_items = {tree.item(i)['values'][0]: i for i in tree.get_children()}
    updated_keys = []

    for host in sorted(active_hosts):
        stat = ping_stats.setdefault(host, {'rtts': [], 'sent': 0, 'received': 0})
        cur = avg = rmin = rmax = "-"
        loss_pct = 100.0

        if host in responses:
            rtt = responses[host]
            stat['rtts'].append(rtt)
            stat['received'] += 1
            cur = format_rtt(rtt)
        else:
            cur = "timeout"

        stat['sent'] += 1
        if stat['rtts']:
            rmin = format_rtt(min(stat['rtts']))
            rmax = format_rtt(max(stat['rtts']))
            avg = format_rtt(sum(stat['rtts']) / len(stat['rtts']))
        if stat['sent'] > 0:
            loss_pct = (1 - stat['received'] / stat['sent']) * 100

        loss_display = get_loss_indicator(loss_pct)
        visible = not show_only_alive or loss_pct < 100.0

        if host in current_items:
            item_id = current_items[host]
            existing_values = list(tree.item(item_id)['values'])
            dns_val = existing_values[6] if len(existing_values) > 6 else "-"
            mac_val = existing_values[7] if len(existing_values) > 7 else "-"
            tree.item(item_id, values=(host, cur, avg, rmin, rmax, loss_display, dns_val, mac_val))
            tree.item(item_id, open=visible, tags=('hidden',) if not visible else ())
        else:
            new_id = tree.insert("", "end", values=(host, cur, avg, rmin, rmax, loss_display, "-", "-"))
            if not visible:
                tree.item(new_id, tags=('hidden',))

    for ip, item_id in current_items.items():
        if ip not in active_hosts:
            tree.delete(item_id)

    apply_sort()

def resolve_background_info():
    for item_id in tree.get_children():
        ip = tree.item(item_id)['values'][0]
        values = list(tree.item(item_id)['values'])
        if values[6] == "-":
            values[6] = resolve_dns(ip)
        if values[7] == "-":
            values[7] = resolve_mac(ip)
        tree.item(item_id, values=values)

def ping_loop():
    global running, start_time
    start_time = time.time()
    while running:
        if not active_hosts:
            time.sleep(1)
            continue
        mp = MultiPing(list(active_hosts))
        mp.send()
        responses, no_responses = mp.receive(1)
        root.after(0, update_display, responses, no_responses)
        time.sleep(INTERVAL_OPTIONS.get(selected_interval.get(), 1))

def start_pinging():
    global running, ping_thread, ping_stats
    if not running:
        running = True
        ping_stats = {}
        add_ips()
        ping_thread = threading.Thread(target=ping_loop, daemon=True)
        ping_thread.start()

def stop_pinging():
    global running, active_hosts
    running = False
    active_hosts.clear()
    for item in tree.get_children():
        tree.delete(item)
    duration_label.config(text="Duration: 0:00:00")


def add_ips():
    new_ips = expand_ips(ip_entry.get())
    added = 0
    for ip in new_ips:
        if ip not in active_hosts:
            active_hosts.add(ip)
            ping_stats[ip] = {'rtts': [], 'sent': 0, 'received': 0}
            new_id = tree.insert("", "end", values=(ip, "-", "-", "-", "-", "-", "-", "-"))
            added += 1
    ip_entry.delete(0, 'end')
    if added > 0:
        print(f"Added {added} new IP(s) to ping list.")


def remove_selected():
    selected_items = tree.selection()
    for item in selected_items:
        ip = tree.item(item)['values'][0]
        if ip in active_hosts:
            active_hosts.remove(ip)
        if ip in ping_stats:
            del ping_stats[ip]
        tree.delete(item)


def toggle_alive_dead():
    global show_only_alive
    show_only_alive = not show_only_alive
    for item_id in tree.get_children():
        values = tree.item(item_id)['values']
        loss_text = values[5]
        loss_pct = 100.0
        try:
            loss_pct = float(''.join(c for c in loss_text if c.isdigit() or c == '.'))
        except:
            pass
        visible = not show_only_alive or loss_pct < 100.0
        tree.item(item_id, open=visible, tags=('hidden',) if not visible else ())


root = tk.Tk()
root.title("Adam's Multi-Ping")
root.geometry("1050x580")
root.minsize(950, 450)

selected_interval = tk.StringVar(value="1 sec")

tk.Label(root, text="Enter IPs or CIDR ranges (comma-separated):").pack(pady=(10, 0))

ip_frame = tk.Frame(root)
ip_frame.pack(pady=5, padx=10, fill='x')

ip_entry = tk.Entry(ip_frame)
ip_entry.insert(0, "172.16.20.0")
ip_entry.pack(side='left', expand=True, fill='x')

cidr_var = tk.StringVar(value="/24")
cidr_options = [f"/{i}" for i in range(8, 33)]
cidr_menu = ttk.OptionMenu(ip_frame, cidr_var, cidr_var.get(), *cidr_options)
cidr_menu.pack(side='left', padx=(5, 0))

def append_cidr():
    ip_text = ip_entry.get().split("/")[0].strip()
    new_text = f"{ip_text}{cidr_var.get()}"
    ip_entry.delete(0, 'end')
    ip_entry.insert(0, new_text)

tk.Button(ip_frame, text="+ Add", command=lambda: [append_cidr(), add_ips()], width=8).pack(side='left', padx=(5, 0))

interval_frame = tk.Frame(root)
interval_frame.pack(pady=5)
tk.Label(interval_frame, text="Interval:").pack(side="left", padx=(0, 5))
interval_menu = ttk.OptionMenu(interval_frame, selected_interval, selected_interval.get(), *interval_label_list)
interval_menu.pack(side="left")

duration_label = tk.Label(root, text="Duration: 0:00:00", font=("Arial", 10, "italic"))
duration_label.pack()

tree_frame = tk.Frame(root)
tree_frame.pack(padx=10, pady=5, fill='both', expand=True)

columns = ("IP", "Current", "Avg", "Min", "Max", "Loss", "DNS", "MAC")
tree = ttk.Treeview(tree_frame, columns=columns, show="headings", selectmode="extended")
for idx, col in enumerate(columns):
    tree.heading(col, text=col, command=lambda _c=idx: sort_treeview(_c))
    tree.column(col, anchor="center", width=100, stretch=True)

vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=tree.yview)
tree.configure(yscrollcommand=vsb.set)
tree.pack(side="left", fill="both", expand=True)
vsb.pack(side="right", fill="y")

btn_frame = tk.Frame(root)
btn_frame.pack(pady=10)
tk.Button(btn_frame, text="Start", command=start_pinging, width=12).pack(side="left", padx=5)
tk.Button(btn_frame, text="Stop All", command=stop_pinging, width=12).pack(side="left", padx=5)
tk.Button(btn_frame, text="Remove Selected", command=remove_selected, width=16).pack(side="left", padx=5)
tk.Button(btn_frame, text="Resolve DNS/MAC", command=resolve_background_info, width=18).pack(side="left", padx=5)
tk.Button(btn_frame, text="Toggle Alive/Dead", command=toggle_alive_dead, width=18).pack(side="left", padx=5)

root.mainloop()
