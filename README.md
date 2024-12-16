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
│   ├── kra_script.py
│   ├── kra1/
│   │   ├── kra1.py
│   │   └── keys/
│   │       ├── kra1_public.pem
│   │       └── kra1_private.pem
│   ├── kra2/
│   │   ├── kra2.py
│   │   └── keys/
│   │       ├── kra2_public.pem
│   │       └── kra2_private.pem
│   ├── kra3/
│   │   ├── kra3.py
│   │   └── keys/
│   │       ├── kra3_public.pem
│   │       └── kra3_private.pem
│   ├── kra4/
│   │   ├── kra4.py
│   │   └── keys/
│   │       ├── kra4_public.pem
│   │       └── kra4_private.pem
│   └── kra5/
│       ├── kra5.py
│       └── keys/
│           ├── kra5_public.pem
│           └── kra5_private.pem
│
├── Shared/
│   └── keys/
│       ├── kra1_public.pem
│       ├── kra2_public.pem
│       ├── kra3_public.pem
│       ├── kra4_public.pem
│       ├── kra5_public.pem
│       ├── krc_public.pem
│       ├── sender_public.pem
│       └── receiver_public.pem
│
├── generate_key/
│   └── GenKey.py
│
└── docker-compose.yml
```
