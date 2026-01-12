# WINRUN
Running windows programs on linux based operating system with WINRUN. By running windows on qemu/kvm manage by libvirt and communicate with Microsoft Remote Desktop app Protocol and our windows management service.

## ⚠️ notice ⚠️

WINRUN is currently in prebeta stage, so some features may not working between difference distro or some hardware, if there any bug you can send report to our email. "yurukoinaba@proton.me"

## How Does It Work?
WINRUN allows you to run Windows programs on Linux. Windows runs as a VM inside a qemu/kvm and manage by libvirt, WINRUN communicate with it by using the "REDFLAG" our windows service to retrieve data from Windows. For compositing applications as native OS-level windows, we use FreeRDP together with Windows's RemoteApp protocol.

## Features

- ✨ User friendly interface ✨ : Simple and user friendly interface that design for new linux users making it feel like a native experience.
- 🪄 Preconfig windows VM 🪄 : WINRUN came with preconfig windows virtual machine for users who don't want to create own virtual machine. ( on WINRUN virtual machine we have windows enterprise ltsc 2019 and windows server 2022 core, so if you want to use it you need to have a windows enterprise product key to activate it or use it unactivate. )
- 🔎 support many programs 🔎 : WINRUN can run many windows programs such as adobe and microsoft office. ( programs that running on WINRUN is running on virtual machine so if you want to play game on it that it has anticheat kernel level it will not work. )
- ⚙️ Full Windows Desktop ⚙️ : You can Access windows desktop by using desktop remote function. it work by using RDP function on windows.
- 🖥️ Hardware passthrough 🖥️ : WINRUN is running libvirt qemu/kvm. so you can add more device to it such as usb flashdrive , webcam and gpu. ( to passthrough gpu you system must have 2 gpu as minimum and this function will work best on desktop pc not recommend using on laptop. )
- 🪽 lightweight 🪽 : WINRUN using less system resources than other similar software. ( WINRUN has it own windows service and drivers to make it lightweight as much as possible. )

