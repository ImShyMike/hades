# hades

transparent message anonymizer

## Installation

Requires Python 3.12+

```bash
uv tool install hades-slack
```

## Usage

### Create Slack apps

Slack has a funny thing called ratelimiting so we need multiple apps so this doesn't take 5 and a half years to complete.

This is automated and needs an "App Configuration Token" from Slack. How do you get one?

- Go to [https://api.slack.com/apps](https://api.slack.com/apps)
- Scroll down to "Your App Configuration Tokens"
- Click "Generate Token"
- Copy the "Access Token" that is generated

```bash
hades create-apps APP_CONFIG_TOKEN_HERE
```

This will create 5 slack apps and save their credentials. (The amount can be changed with the `--count` flag.)

### Authenticating the Slack apps

What we actually need are user tokens for each app. To get those, run:

```bash
hades install-apps
```

This will open a browser window for each app and ask you to authorize it. After authorizing all apps, the user tokens will be saved to `apps.json`.

### Downloading your messages

Before any operation, you will need to make a full download of your messages. This is done with:

```bash
hades download YOUR_USER_ID_HERE --apps apps.json
```

This will use the apps you created to download all your messages and save them to `slack_messages.db`.

Use `--resume` to continue a previously interrupted download.

Use `--purge` to delete any existing messages in the database before downloading.

### Seeing your message stats

Now that you have your messages downloaded, you can see some stats about them with:

```bash
hades stats
```

### Encrypting your messages

To encrypt your messages, run:

```bash
hades encrypt YOUR_PASSWORD_HERE ENCRYPT_OLDER_THAN --apps apps.json --execute
```

`ENCRYPT_OLDER_THAN` is the amount of days old a message has to be to be encrypted. For example, `30` will encrypt all messages older than 30 days and `0` will encrypt all messages.

Removing the `--execute` flag will do a dry run and show you how many messages would be encrypted without actually encrypting them on Slack.

#### Encryption modes

Use `--mode` to control what replaces your message text:

- `text` (default): Replace with custom text via `--text` (default: `[anonymized with hades]`)
- `random`: Replace with random hex string
- `invisible`: Make the message invisible

### Decrypting your messages

To decrypt your messages you will need to have a fresh download of your messages (run the `download` command again) and then run:

```bash
hades decrypt YOUR_PASSWORD_HERE DECRYPT_YOUNGER_THAN --apps apps.json --execute
```

`DECRYPT_YOUNGER_THAN` is the amount of days old a message has to be to be decrypted. For example, `30` will decrypt all messages younger than 30 days and `0` will decrypt all messages.

Removing the `--execute` flag will do a dry run and show you how many messages would be decrypted without actually decrypting them on Slack.
