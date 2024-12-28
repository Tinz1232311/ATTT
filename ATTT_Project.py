import os
import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk
from scapy.all import sniff, IP, TCP, UDP, Raw, get_if_list  # type: ignore
import threading
import time
import subprocess  # Thêm module subprocess để ping IP
from queue import Queue

# Queue to communicate between threads
packet_queue = Queue()

# Callback function to process captured packets
def process_packet(packet):
    try:
        packet_info = ""
        
        # Check if the packet contains an IP layer
        if IP in packet:
            ip_layer = packet[IP]
            packet_info += f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
            packet_info += f"Source IP: {ip_layer.src}\n"
            packet_info += f"Destination IP: {ip_layer.dst}\n"
            packet_info += f"Protocol: {ip_layer.proto}\n"

            # Check if the packet contains a TCP layer
            if TCP in packet:
                tcp_layer = packet[TCP]
                packet_info += f"TCP Source Port: {tcp_layer.sport}\n"
                packet_info += f"TCP Destination Port: {tcp_layer.dport}\n"
                packet_info += f"TCP Flags: {tcp_layer.flags}\n"

                if Raw in packet:
                    payload_data = packet[Raw].load
                    if b"HTTP" in payload_data:
                        packet_info += "HTTP Payload Detected!\n"
                        packet_info += f"{payload_data.decode(errors='ignore')[:100]}\n"
                    else:
                        packet_info += "Non-HTTP payload or encrypted data detected.\n"
                        packet_info += f"Payload (hex): {payload_data.hex()[:100]}\n"
            
            # Check if the packet contains a UDP layer
            elif UDP in packet:
                udp_layer = packet[UDP]
                packet_info += f"UDP Source Port: {udp_layer.sport}\n"
                packet_info += f"UDP Destination Port: {udp_layer.dport}\n"

        else:
            packet_info += "No IP Layer detected.\n"

        packet_info += "-" * 50 + "\n"

        # Put the packet info in the queue to update GUI
        packet_queue.put(packet_info)
        
        # Debug print the captured packet summary
        print(f"Captured packet: {packet.summary()}")

    except Exception as e:
        print(f"Error processing packet: {e}")  # Log the error to the console
        packet_queue.put(f"Error processing packet: {e}\n")

# Worker thread to process packets from the queue and update the GUI
def packet_worker():
    while True:
        packet_info = packet_queue.get()
        if packet_info is None:
            break  # Exit the worker thread
        update_gui(packet_info)
        packet_queue.task_done()

# Function to update the GUI with packet info
def update_gui(packet_info):
    text_box.after(0, lambda: text_box.insert(tk.END, packet_info))
    text_box.after(0, lambda: text_box.yview(tk.END))

# Sniff packets on a specific interface
def start_sniffing(interface, count):
    try:
        text_box.after(0, lambda: text_box.insert(tk.END, f"Starting packet capture on interface: {interface}\n"))
        text_box.after(0, lambda: text_box.insert(tk.END, f"This action may take a few minutes. Please wait for the proccess!\n"))
        # Sniff packets with an "ip" filter and specified count
        sniff(iface=interface, prn=process_packet, count=count, store=0, filter="ip")
    except Exception as e:
        text_box.after(0, lambda: text_box.insert(tk.END, f"Error during packet capture: {e}\n"))

# Start sniffing from the selected interface in the combobox
def start_sniffing_from_selected_interface(interfaces_combobox, count_entry):
    try:
        selected_interface = interfaces_combobox.get()
        if selected_interface == "No network interfaces available.":
            messagebox.showwarning("Selection Error", "No network interfaces available for sniffing.")
            return
        
        count = int(count_entry.get())
        if count <= 0:
            messagebox.showwarning("Input Error", "Please enter a positive number of packets to capture.")
            return

        start_sniffing_thread(selected_interface, count)
    except ValueError:
        messagebox.showerror("Input Error", "Please enter a valid number for packet count.")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {e}")

# Start sniffing in a separate thread
def start_sniffing_thread(interface, count):
    sniff_thread = threading.Thread(target=start_sniffing, args=(interface, count))
    sniff_thread.daemon = True
    sniff_thread.start()

# Ping the IP address using subprocess
def ping_ip_from_entry():
    ip_to_ping = ping_ip_entry.get()
    if ip_to_ping:
        ping_thread = threading.Thread(target=ping_ip, args=(ip_to_ping,))
        ping_thread.start()
    else:
        messagebox.showwarning("Input Error", "Please enter a valid IP address.")

# Ping function to run in a separate thread
def ping_ip(ip_to_ping):
    try:
        # Execute the ping command using subprocess
        response = subprocess.run(["ping", ip_to_ping, "-n", "4"], capture_output=True, text=True)
        if response.returncode == 0:
            messagebox.showinfo("Ping Success", f"Ping successful to {ip_to_ping}.\n{response.stdout}")
        else:
            messagebox.showerror("Ping Failed", f"Ping failed to {ip_to_ping}.\n{response.stderr}")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred while pinging the IP: {e}")

# Create the main window and text box for displaying packet info
def create_gui():
    global ping_ip_entry, text_box  # Đảm bảo các biến này có thể được truy cập trong các hàm khác

    root = tk.Tk()
    root.title("Network Packet Capture")
    
    root.configure(bg="#2e3b4e")
    root.geometry("800x600")

    frame = tk.Frame(root, bg="#2e3b4e")
    frame.pack(fill="both", expand=True)

    title_label = tk.Label(frame, text="Network Packet Capture", font=("Arial", 18, "bold"), fg="#ffffff", bg="#2e3b4e")
    title_label.pack(pady=10)

    text_box = scrolledtext.ScrolledText(frame, width=90, height=20, font=("Courier New", 10), bg="#f5f5f5", fg="#333333", wrap=tk.WORD)
    text_box.pack(padx=10, pady=10, fill="both", expand=True)

    interfaces_label = tk.Label(frame, text="Available Network Interfaces:", font=("Arial", 12, "bold"), fg="#ffffff", bg="#2e3b4e")
    interfaces_label.pack(pady=10)

    interfaces_combobox = ttk.Combobox(frame, font=("Arial", 12), state="readonly")
    interfaces = get_if_list()
    if interfaces:
        interfaces_combobox['values'] = interfaces
        interfaces_combobox.set(interfaces[0])
    else:
        interfaces_combobox['values'] = ["No network interfaces available."]
        interfaces_combobox.set("No network interfaces available.")
    interfaces_combobox.pack(pady=10)

    count_label = tk.Label(frame, text="Number of packets to capture:", font=("Arial", 12, "bold"), fg="#ffffff", bg="#2e3b4e")
    count_label.pack(pady=5)

    count_entry = tk.Entry(frame, font=("Arial", 12), width=10)
    count_entry.insert(0, "3")
    count_entry.pack(pady=5)

    start_button = tk.Button(frame, text="Start Sniffing", font=("Arial", 14), bg="#4CAF50", fg="#ffffff", 
                             command=lambda: start_sniffing_from_selected_interface(interfaces_combobox, count_entry))
    start_button.pack(pady=10)

    # Ping Button
    ping_button = tk.Button(frame, text="Ping IP", font=("Arial", 14), bg="#007BFF", fg="#ffffff", 
                            command=ping_ip_from_entry)
    ping_button.pack(pady=10)

    # Entry for IP address to ping
    ping_ip_entry = tk.Entry(frame, font=("Arial", 12), width=20)
    ping_ip_entry.insert(0, "Enter IP to ping")
    ping_ip_entry.pack(pady=5)

    # Start the worker thread for updating the GUI
    threading.Thread(target=packet_worker, daemon=True).start()

    root.mainloop()

# Main entry point to the script
if __name__ == "__main__":
    create_gui()

print("This code demonstrates the improved Network Packet Capture script.")
