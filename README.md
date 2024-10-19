# AIFeatures Documentation

The `AIFeatures` model is used to manage feature flags for AI agents. These flags enable or disable specific functionalities within the application. Each feature flag is associated with an agent and can be toggled on or off based on the requirements.

## Feature Flags

### 1. ENABLE_MESSAGE
- **Description**: Enables the functionality to send text messages to users.
- **Value**: The phone number from which messages will be sent.
- **Enabled**: When set to `true`, the `send_message` function is active.

### 2. ENABLE_MESSAGE_INACTIVE
- **Description**: Controls the active state of the `send_message` function.
- **Value**: Not applicable.
- **Enabled**: When set to `true`, the `send_message` function is inactive.

### 3. ENABLE_TRANSFER
- **Description**: Enables the functionality to transfer calls to a specified target.
- **Value**: Not applicable.
- **Enabled**: When set to `true`, the `transfer` function is active.

### 4. ENABLE_TRANSFER_INACTIVE
- **Description**: Controls the active state of the `transfer` function.
- **Value**: Not applicable.
- **Enabled**: When set to `true`, the `transfer` function is inactive.

### 5. TRANSFER_TABLE
- **Description**: Provides a mapping of transfer targets to their respective contact details.
- **Value**: A string formatted as `key1:value1|key2:value2|...`, where each key-value pair represents a target and its contact.
- **Enabled**: Not applicable.

### 6. API_NINJAS_KEY
- **Description**: Stores the API key for accessing the API Ninjas service.
- **Value**: The API key string.
- **Enabled**: When set to `true`, the API key is considered valid and usable.

### 7. API_NINJAS_WEATHER
- **Description**: Enables the functionality to fetch weather information for a specified city.
- **Value**: Not applicable.
- **Enabled**: When set to `true`, the `get_weather` function is active.

### 8. API_NINJAS_JOKES
- **Description**: Enables the functionality to fetch and tell jokes.
- **Value**: Not applicable.
- **Enabled**: When set to `true`, the `get_joke` function is active.

### 9. API_NINJAS_TRIVIA
- **Description**: Enables the functionality to fetch trivia questions.
- **Value**: Not applicable.
- **Enabled**: When set to `true`, the `get_trivia` function is active.

### 10. API_NINJAS_FACTS
- **Description**: Enables the functionality to fetch random facts.
- **Value**: Not applicable.
- **Enabled**: When set to `true`, the `get_fact` function is active.

### 11. API_NINJAS_QUOTES
- **Description**: Enables the functionality to fetch and display quotes.
- **Value**: Not applicable.
- **Enabled**: When set to `true`, the `get_quote` function is active.

### 12. API_NINJAS_COCKTAILS
- **Description**: Enables the functionality to fetch cocktail recipes.
- **Value**: Not applicable.
- **Enabled**: When set to `true`, the `get_cocktail` function is active.

### 13. DATA_SPHERE
- **Description**: Enables the functionality to access and manage data within the Data Sphere environment.
- **Value**: The document ID used to identify and access specific data within the Data Sphere.
- **Enabled**: When set to `true`, the `data_sphere` function is active.

### 14. ENABLE_RECORD
- **Description**: Enables the functionality to record audio.
- **Value**: The format of the recording, which can be either `wav` or `mp3`.
- **Enabled**: When set to `true`, the recording function is active. By default, recordings are made in stereo.


## Usage

Each feature flag can be managed through the application's interface or API. The flags are stored in the database and can be queried or updated as needed. The `enabled` attribute determines whether the feature is active, while the `value` attribute provides additional configuration details when necessary.

## Example

To enable the message sending feature for an agent, set the `ENABLE_MESSAGE` flag to `true` and provide a valid phone number in the `value` field.
