### **Agent Management**

#### **Get All Agents**
- **Endpoint:** `GET /api/v1/agents`
- **Description:** Retrieves a list of all agents.
- **Response:** JSON array of agent objects.

#### **Get Agent by ID**
- **Endpoint:** `GET /api/v1/agents/<int:agent_id>`
- **Description:** Retrieves details of a specific agent.
- **Parameters:**
  - `agent_id` (int): The ID of the agent.
- **Response:** JSON object with agent details.

#### **Create Agent**
- **Endpoint:** `POST /api/v1/agents`
- **Description:** Creates a new agent.
- **Request Body:** JSON object with required agent details.
- **Response:** JSON object confirming creation with agent ID.

#### **Update Agent**
- **Endpoint:** `PUT /api/v1/agents/<int:agent_id>`
- **Description:** Updates details of an existing agent.
- **Parameters:**
  - `agent_id` (int): The ID of the agent.
- **Request Body:** JSON object with updated agent details.
- **Response:** JSON object confirming the update.

#### **Delete Agent**
- **Endpoint:** `DELETE /api/v1/agents/<int:agent_id>`
- **Description:** Deletes a specific agent.
- **Parameters:**
  - `agent_id` (int): The ID of the agent.
- **Response:** JSON object confirming deletion.

#### **Clone Agent**
- **Endpoint:** `POST /api/v1/agents/<int:agent_id>/clone`
- **Description:** Creates a clone of an existing agent.
- **Parameters:**
  - `agent_id` (int): The ID of the agent to clone.
- **Response:** JSON object with new cloned agent details.

---

### **Debug Logs**

#### **Get Debug Logs**
- **Endpoint:** `GET /api/v1/agents/<int:agent_id>/debuglogs`
- **Description:** Retrieves debug logs for a specific agent.
- **Parameters:**
  - `agent_id` (int): The ID of the agent.
- **Response:** JSON array of debug log entries.

#### **Delete Debug Logs**
- **Endpoint:** `DELETE /api/v1/agents/<int:agent_id>/debuglogs`
- **Description:** Deletes all debug logs for a specific agent.
- **Parameters:**
  - `agent_id` (int): The ID of the agent.
- **Response:** JSON object confirming deletion.

---

### **Hints**

#### **Get All Hints**
- **Endpoint:** `GET /api/v1/agents/<int:agent_id>/hints`
- **Description:** Retrieves all hints associated with an agent.
- **Parameters:**
  - `agent_id` (int): The ID of the agent.
- **Response:** JSON array of hint objects.

#### **Get Hint by ID**
- **Endpoint:** `GET /api/v1/agents/<int:agent_id>/hints/<int:hint_id>`
- **Description:** Retrieves a specific hint for an agent.
- **Parameters:**
  - `agent_id` (int): The ID of the agent.
  - `hint_id` (int): The ID of the hint.
- **Response:** JSON object with hint details.

#### **Create Hint**
- **Endpoint:** `POST /api/v1/agents/<int:agent_id>/hints`
- **Description:** Adds a new hint to an agent.
- **Request Body:** JSON object with hint details.
- **Response:** JSON object confirming creation.

#### **Update Hint**
- **Endpoint:** `PUT /api/v1/agents/<int:agent_id>/hints/<int:hint_id>`
- **Description:** Updates a specific hint for an agent.
- **Parameters:**
  - `agent_id` (int): The ID of the agent.
  - `hint_id` (int): The ID of the hint.
- **Request Body:** JSON object with updated hint details.
- **Response:** JSON object confirming the update.

#### **Delete Hint**
- **Endpoint:** `DELETE /api/v1/agents/<int:agent_id>/hints/<int:hint_id>`
- **Description:** Deletes a specific hint.
- **Parameters:**
  - `agent_id` (int): The ID of the agent.
  - `hint_id` (int): The ID of the hint.
- **Response:** JSON object confirming deletion.

---

### **Pronunciation Management**

#### **Get All Pronunciations**
- **Endpoint:** `GET /api/v1/agents/<int:agent_id>/pronounce`
- **Description:** Retrieves all pronunciation entries for an agent.
- **Parameters:**
  - `agent_id` (int): The ID of the agent.
- **Response:** JSON array of pronunciation entries.

#### **Get Pronunciation by ID**
- **Endpoint:** `GET /api/v1/agents/<int:agent_id>/pronounce/<int:pronounce_id>`
- **Description:** Retrieves a specific pronunciation entry.
- **Parameters:**
  - `agent_id` (int): The ID of the agent.
  - `pronounce_id` (int): The ID of the pronunciation entry.
- **Response:** JSON object with pronunciation details.

#### **Create Pronunciation**
- **Endpoint:** `POST /api/v1/agents/<int:agent_id>/pronounce`
- **Description:** Adds a new pronunciation entry.
- **Request Body:** JSON object with pronunciation details.
- **Response:** JSON object confirming creation.

#### **Update Pronunciation**
- **Endpoint:** `PUT /api/v1/agents/<int:agent_id>/pronounce/<int:pronounce_id>`
- **Description:** Updates a specific pronunciation entry.
- **Parameters:**
  - `agent_id` (int): The ID of the agent.
  - `pronounce_id` (int): The ID of the pronunciation entry.
- **Request Body:** JSON object with updated pronunciation details.
- **Response:** JSON object confirming the update.

#### **Delete Pronunciation**
- **Endpoint:** `DELETE /api/v1/agents/<int:agent_id>/pronounce/<int:pronounce_id>`
- **Description:** Deletes a specific pronunciation entry.
- **Parameters:**
  - `agent_id` (int): The ID of the agent.
  - `pronounce_id` (int): The ID of the pronunciation entry.
- **Response:** JSON object confirming deletion.

---

### **SignalWire Parameters**

#### **Get All SignalWire Parameters**
- **Endpoint:** `GET /api/v1/signalwire`
- **Description:** Retrieves all SignalWire parameters.
- **Response:** JSON array of SignalWire parameters.

#### **Get SignalWire Parameter by ID**
- **Endpoint:** `GET /api/v1/signalwire/<int:param_id>`
- **Description:** Retrieves a specific SignalWire parameter.
- **Parameters:**
  - `param_id` (int): The ID of the SignalWire parameter.
- **Response:** JSON object with parameter details.

#### **Create SignalWire Parameter**
- **Endpoint:** `POST /api/v1/signalwire`
- **Description:** Adds a new SignalWire parameter.
- **Request Body:** JSON object with parameter details.
- **Response:** JSON object confirming creation.

#### **Update SignalWire Parameter**
- **Endpoint:** `PUT /api/v1/signalwire/<int:param_id>`
- **Description:** Updates a specific SignalWire parameter.
- **Parameters:**
  - `param_id` (int): The ID of the SignalWire parameter.
- **Request Body:** JSON object with updated parameter details.
- **Response:** JSON object confirming the update.

#### **Delete SignalWire Parameter**
- **Endpoint:** `DELETE /api/v1/signalwire/<int:param_id>`
- **Description:** Deletes a specific SignalWire parameter.
- **Parameters:**
  - `param_id` (int): The ID of the SignalWire parameter.
- **Response:** JSON object confirming deletion.

---
