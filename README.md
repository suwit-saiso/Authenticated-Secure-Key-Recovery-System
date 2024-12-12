# Authenticated-Secure-Key-Recovery-System

## `Folder Structure`
```
Projects/
├── Sender/
│   ├── Dockerfile.sender
│   ├── sender.py
│   └── keys/
│       ├── sender_private.pem
│       └── sender_public.pem
│
├── Receiver/
│   ├── Dockerfile.receiver
│   ├── receiver.py
│   └── keys/
│       ├── receiver_private.pem
│       └── receiver_public.pem
│
├── KRC/
│   ├── Dockerfile.KRC
│   ├── krc.py
│   └── keys/
│       ├── krc_private.pem
│       └── krc_public.pem
│
├── KRA/
│   ├── Dockerfile.KRA
│   ├── kra.py
│   └── keys/
│       ├── kra_private.pem
│       └── kra_public.pem
│
└── docker-compose.yml
```