# WebCableDiag

At first, I wanted a tool to search MAC addresses in a star topology for a single site as I couldn't get along with netdisco.
As a colleague wanted to have a tool for cable diagonistics at this time, I combined these.

I tried to vibe-code this project using Copilot.
However, in the parsing of the TDR output, I was quicker fixing it manually.
I skimmed the code and added some comments what can be improved.

I have no experience generating whole project using LLMs.
It chose Flask and using requirements.txt on its own.
I guess this will cause problems in future.
As most of the prompts were in German, the interface is also in German, no internationalization for now and some terms in the code might be a bit off.
I will ask the AI to fix this in some future.

## Features

This tool helps network administrators and in-field technicians without management access:

- Lookup switchport of a MAC address (in a star topology)
- View port descriptions and states
- Run TDR cable diagnostics (for twisted pair)
- Multi-site support
- German interface, no English for now

Currently only for Cisco switches.

## Installation

Of course, use a virtual environment.
Due to requirements.txt, fun is limited to Python 3.9 and 3.11.

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Create a inventory.yaml in the project root based on inventory.yaml.sample and adjust it to your environment.
You can use most parameters known to netmiko for AAA at device-level as well as at global level.

### Dev server

```bash
flask run
```

### Production server

TODO
