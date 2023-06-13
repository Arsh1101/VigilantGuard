# Vigilant Guard 🛡️
VigilantGuard is a lightweight security monitoring service that uses Go and eBPF to produce SIGMA rules with a communication module to collect logs in distributed environments. The primary purpose of VigilantGuard is to mitigate microservice architecture risks by collecting standard SIGMA rules. ✅

This repository is based on the tutorial and code from [masmullin2000's](https://github.com/masmullin2000) repository. I have extended it to include a communication module and additional features to better suit our use case. 📌

## Features
- Uses eBPF to capture data. 🐝
- Produces SIGMA rules that can be used with various security information and event management (SIEM) systems. ✔️
- Supports communication between multiple instances in a distributed environment to collect logs (using gRPC). 📡
- Lightweight and designed for microservice architectures. ⚡
- Uses Golang to implement the logic. 🐹
