import psutil
import os
from datetime import datetime
import socket
import platform
import shutil

program_types = ["Python", "PHP", "Shell", "Java", "NodeJS", "Ruby", "Go", "Perl", "C", "C++"]

def clear_terminal():
    os.system('cls' if platform.system() == 'Windows' else 'clear')

def print_logo():
    logo = r"""
 /$$$$$$$$                            /$$$$$$$$                           /$$      
| $$_____/                           |__  $$__/                          | $$      
| $$       /$$   /$$  /$$$$$$   /$$$$$$$| $$  /$$$$$$  /$$$$$$   /$$$$$$$| $$   /$$
| $$$$$   |  $$ /$$/ /$$__  $$ /$$_____/| $$ /$$__  $$|____  $$ /$$_____/| $$  /$$/
| $$__/    \  $$$$/ | $$$$$$$$| $$      | $$| $$  \__/ /$$$$$$$| $$      | $$$$$$/ 
| $$        >$$  $$ | $$_____/| $$      | $$| $$      /$$__  $$| $$      | $$_  $$ 
| $$$$$$$$ /$$/\  $$|  $$$$$$$|  $$$$$$$| $$| $$     |  $$$$$$$|  $$$$$$$| $$ \  $$
|________/|__/  \__/ \_______/ \_______/|__/|__/      \_______/ \_______/|__/  \__/
                                                                                   
                                                                                   
                                                                                   
                   ExecTrack - Process Inspector
"""
    print(logo)

def list_programs_by_type(selected_type):
    result = []
    for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'create_time']):
        try:
            name = proc.info['name'].lower() if proc.info['name'] else ""
            cmdline = " ".join(proc.info['cmdline']).lower() if proc.info['cmdline'] else ""
            exe_path = proc.info['exe'] or (cmdline.split()[0] if cmdline else None)
            ctime = datetime.fromtimestamp(proc.info['create_time']).strftime("%Y-%m-%d %H:%M:%S") if proc.info['create_time'] else "Unknown"

            match = False
            if selected_type == "Python" and ("python" in name or ".py" in cmdline):
                match = True
            elif selected_type == "PHP" and ("php" in name or ".php" in cmdline):
                match = True
            elif selected_type == "Shell" and ("bash" in name or "sh" in name or ".sh" in cmdline):
                match = True
            elif selected_type == "Java" and ("java" in name or ".jar" in cmdline):
                match = True
            elif selected_type == "NodeJS" and ("node" in name or ".js" in cmdline):
                match = True
            elif selected_type == "Ruby" and ("ruby" in name or ".rb" in cmdline):
                match = True
            elif selected_type == "Go" and ("go" in name or ".go" in cmdline):
                match = True
            elif selected_type == "Perl" and ("perl" in name or ".pl" in cmdline):
                match = True
            elif selected_type == "C" and ("c" in name):
                match = True
            elif selected_type == "C++" and ("cpp" in name):
                match = True

            if match and exe_path:
                try:
                    connections = []
                    for conn in proc.connections(kind='inet'):
                        laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else ""
                        raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else ""
                        proto = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
                        state = conn.status
                        if state == psutil.CONN_LISTEN:
                            state = "LISTEN"
                        if not raddr and state != "ESTABLISHED":
                            state = "LISTEN" if state == "NONE" else state
                        connections.append(f"{state}/{proto} {laddr}->{raddr if raddr else ''}".strip("->"))
                    net_status = "; ".join(connections) if connections else "None"
                    if len(net_status) > 60:
                        net_status = net_status[:57] + "..."
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    net_status = "None"

                try:
                    startup = "Yes" if os.path.exists(f"/etc/systemd/system/{os.path.basename(exe_path)}") else "No"
                except:
                    startup = "Unknown"

                result.append({
                    "name": exe_path,
                    "network": net_status,
                    "created": ctime,
                    "startup": startup
                })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
        except Exception as e:
            print(f"[Error] {e}")
    return result

def search_program(search_type, search_value):
    result = []
    port = None
    if search_type == "port":
        try:
            port = int(search_value)
        except ValueError:
            return []
    for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'create_time']):
        try:
            proc_name = proc.info['name'] if proc.info['name'] else ""
            cmdline_list = proc.info['cmdline'] if proc.info['cmdline'] else []
            cmdline = " ".join(cmdline_list).lower()
            exe_path = proc.info['exe'] or (cmdline_list[0] if cmdline_list else None)
            display_name = exe_path or proc_name or "Unknown"
            ctime = datetime.fromtimestamp(proc.info['create_time']).strftime("%Y-%m-%d %H:%M:%S") if proc.info['create_time'] else "Unknown"

            match = False
            if search_type == "name":
                if search_value.lower() in cmdline or search_value.lower() in display_name.lower():
                    match = True
            elif search_type == "port":
                try:
                    for conn in proc.connections(kind='inet'):
                        if (conn.laddr and conn.laddr.port == port) or (conn.raddr and conn.raddr.port == port):
                            match = True
                            break
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    continue

            if match:
                try:
                    connections = []
                    for conn in proc.connections(kind='inet'):
                        if search_type != "port" or ((conn.laddr and conn.laddr.port == port) or (conn.raddr and conn.raddr.port == port)):
                            laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else ""
                            raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else ""
                            proto = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
                            state = conn.status
                            if state == psutil.CONN_LISTEN:
                                state = "LISTEN"
                            if not raddr and state != "ESTABLISHED":
                                state = "LISTEN" if state == "NONE" else state
                            connections.append(f"{state}/{proto} {laddr}->{raddr if raddr else ''}".strip("->"))
                    net_status = "; ".join(connections) if connections else "None"
                    if len(net_status) > 60:
                        net_status = net_status[:57] + "..."
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    net_status = "Access Denied"

                try:
                    if exe_path:
                        startup = "Yes" if os.path.exists(f"/etc/systemd/system/{os.path.basename(exe_path)}") else "No"
                    else:
                        startup = "N/A"
                except:
                    startup = "Unknown"

                result.append({
                    "name": display_name,
                    "network": net_status,
                    "created": ctime,
                    "startup": startup
                })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
        except Exception as e:
            print(f"[Error] {e}")
    return result

def print_programs(programs, title):
    if not programs:
        print("No programs found.")
        return
    term_width = shutil.get_terminal_size((80, 24)).columns
    max_name = max([len(p['name']) for p in programs] + [12])
    max_network = max([len(p['network']) for p in programs] + [7])
    max_created = max([len(p['created']) for p in programs] + [7])
    max_startup = max([len(p['startup']) for p in programs] + [7])
    name_w = min(max_name, 60)
    network_w = min(max_network, 65)
    created_w = min(max_created, 20)
    startup_w = min(max_startup, 8)
    total = name_w + network_w + created_w + startup_w + 4*3 + 4  # for | and spaces
    while total > term_width and (name_w > 20 or network_w > 20):
        if network_w > 20:
            network_w -= 1
        if name_w > 20:
            name_w -= 1
        total = name_w + network_w + created_w + startup_w + 4*3 + 4
    print(title)
    sep = f"+{'-'*(name_w+2)}+{'-'*(network_w+2)}+{'-'*(created_w+2)}+{'-'*(startup_w+2)}+"
    print(sep)
    print(f"| {'Program Path':<{name_w}} | {'Network':<{network_w}} | {'Created':<{created_w}} | {'Startup':<{startup_w}} |")
    print(sep)
    for p in programs:
        name = p['name'][:name_w]
        network = p['network'][:network_w - 3] + "..." if len(p['network']) > network_w else p['network']
        created = p['created'][:created_w]
        startup = p['startup'][:startup_w]
        print(f"| {name:<{name_w}} | {network:<{network_w}} | {created:<{created_w}} | {startup:<{startup_w}} |")
    print(sep)

def search_menu():
    while True:
        print("\n--- Search Menu ---")
        print("1. Search by port")
        print("2. Search by name (include extension like .sh, .py, .cs)")
        print("3. Go back to home")
        choice = input("Enter number: ").strip()
        if choice.lower() == "clear":
            clear_terminal()
            print_logo()
            continue
        if choice == "1":
            port = input("Enter port number: ").strip()
            if port.lower() == "clear":
                clear_terminal()
                print_logo()
                continue
            try:
                int(port)
            except ValueError:
                print("Invalid port number.")
                continue
            results = search_program("port", port)
            print_programs(results, "\nFound programs:")
        elif choice == "2":
            name = input("Enter program name with extension: ").strip()
            if name.lower() == "clear":
                clear_terminal()
                print_logo()
                continue
            results = search_program("name", name)
            print_programs(results, "\nFound programs:")
        elif choice == "3":
            return
        else:
            print("Invalid choice.")
            continue

def main():
    clear_terminal()
    print_logo()
    if platform.system() != 'Windows' and os.getuid() != 0:
        print("Warning: Run as sudo to access all system processes and connections.")
    elif platform.system() == 'Windows' and not psutil.Process(os.getpid()).is_running_as_admin():
        print("Warning: Run as administrator to access all system processes and connections.")
    while True:
        print("\nSelect a program type to list running processes:")
        for i, pt in enumerate(program_types, 1):
            print(f"{i}. {pt}")
        print("11. Search by name or port")
        choice = input("Enter number: ").strip()
        if choice.lower() == "clear":
            clear_terminal()
            print_logo()
            continue
        if choice == "11":
            search_menu()
            continue
        try:
            choice = int(choice)
            if choice < 1 or choice > 10:
                print("Invalid selection.")
                continue
        except ValueError:
            print("Invalid input.")
            continue

        selected_type = program_types[choice - 1]
        programs = list_programs_by_type(selected_type)
        print_programs(programs, f"\nRunning {selected_type} programs:")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nExiting...")