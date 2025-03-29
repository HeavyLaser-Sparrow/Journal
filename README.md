# Encrypted Journal

An encrypted journal application built using Python, Tkinter, SQLite, and Fernet encryption. This application allows users to store and manage journal entries securely, with encryption applied to the journal content.

## Features

- **Secure Storage**: Entries are encrypted using Fernet encryption before being saved to the database.
- **Security**: Please remember to hide the key.key file after first running of code, and then manually put it back when want to use it
- **User-friendly Interface**: Built using Tkinter for easy interaction.
- **Markdown Support**: Entries can be written using Markdown formatting.
- **Tagging System**: Users can tag journal entries for better organization.
- **Entry Management**: Save, delete, and view entries with a simple interface.
- **Keyboard Shortcuts**:
  - `Ctrl + S` → Save entry
  - `Ctrl + Backspace` → Delete selected entry

## Installation

### Prerequisites

Ensure you have Python installed (version 3.6 or later recommended).

### Required Libraries

Install the necessary dependencies by running:

```sh
pip install cryptography markdown

