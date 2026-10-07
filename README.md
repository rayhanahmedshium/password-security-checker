# Password Security Checker

A command-line tool that rates how strong a password is and checks whether it has shown up in a real data breach, without ever sending the password anywhere.

## Why I built this

Most password meters only check length and character types. Attackers don't guess randomly, though. They try leaked passwords and common patterns first. This tool checks for the things attackers actually exploit, and uses the same privacy technique (k-anonymity) that services like Firefox Monitor and 1Password use for breach checks.

## Features

- **Strength score (0-100)** based on length, character variety, and estimated entropy
- **Pattern detection:** keyboard runs (`qwer`, `asdf`), alphabet and number sequences (`abcd`, `4321`), repeated characters (`aaa`)
- **Common password check** against a list of the most-used passwords
- **Breach check** using the Have I Been Pwned Pwned Passwords API with k-anonymity
- **Hidden input:** the password is typed with `getpass`, so it never appears on screen or in shell history

## How the breach check stays private

```
password  ──SHA-1──►  5BAA6 1E4C9B93F3F0682250B6CF8331B7EE68FD8
                      └─┬─┘ └──────────────┬──────────────────┘
                 sent to API         kept on your machine
```

1. The password is hashed with SHA-1 locally.
2. Only the first 5 hex characters are sent to the API.
3. The API returns every leaked hash starting with those 5 characters (usually several hundred).
4. The tool searches that list locally for the remaining 35 characters.

The API never learns the password or its full hash. The tests include a check that only a 5-character prefix is ever sent.

## Example

Checking `qwerty123!` in offline mode:

```
$ python password_checker.py --offline
Password to check (input hidden):

Strength : Weak (50/100)
Length   : 10 characters
Entropy  : ~61.1 bits
  - Use at least 12 characters.
  - Contains a predictable sequence (like 'abcd' or 'qwer').
```

With the breach check on, a leaked password adds a line like `FOUND IN BREACHES: seen N times. Do not use this password.`

| Password | Rating | Why |
|---|---|---|
| `password` | Weak (0) | Most common password |
| `qwerty123!` | Weak (50) | Keyboard pattern, under 12 characters |
| `Summer2024` | Moderate (55) | Decent mix, but short and predictable |
| `correct-horse-battery-staple` | Strong (80) | Long passphrase |

## How to run

No third-party packages are needed for the tool itself (standard library only).

```bash
python password_checker.py            # full check
python password_checker.py --offline  # skip the breach lookup

pip install pytest
python -m pytest tests                # tests run offline using a fake API response
```

## Limitations

- The entropy number is a brute-force estimate. It overrates passwords built from dictionary words with predictable substitutions (like `P@ssw0rd`), which is why the pattern and breach checks also matter.
- The built-in common-password list is short. A production version would load a larger list such as the top 100,000 from SecLists.

## Skills used

Python, cryptographic hashing (SHA-1), k-anonymity, REST API usage, input validation, pytest with mocked network calls
