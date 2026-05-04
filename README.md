# Double Ratchet Signal Demo

This project extends a simple Signal-style chat app with Double Ratchet logic.
The main focus is the symmetric-key ratchet: every message advances the chain
key and derives a fresh one-time message key.

## Build

```bash
cd build
make
```

Run the provided tests:

```bash
./unit_tests
```

## Run Two Clients

Open two terminals.

Terminal 1:

```bash
cd build
./signal_app listen localhost 3000
```

Terminal 2:

```bash
cd build
./signal_app connect localhost 3000
```

Then type messages in either terminal.

## Demo: Show Different Message Keys

For presentation only, enable short message-key fingerprints:

Terminal 1:

```bash
cd build
SIGNAL_DEMO_KEYS=1 ./signal_app listen localhost 3000
```

Terminal 2:

```bash
cd build
SIGNAL_DEMO_KEYS=1 ./signal_app connect localhost 3000
```

Example output:

```text
[demo send] N=0 message_key_prefix=...
[demo send] N=1 message_key_prefix=...
```

`N` is the message index in the current chain. `message_key_prefix` is the
first few hex characters of the derived one-time message key. Different
prefixes show that the symmetric-key ratchet derives a fresh key for each
message.

In a real messenger, message keys should never be printed. This flag is only
for the class demo.

## Quit

Use `Ctrl + D` for a clean disconnect. Use `Ctrl + C` if the process is stuck.
