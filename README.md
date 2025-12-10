# simple-tools-security-scanner-kubernetes
Simple tools based on MCP architecture using Hexstrike AI as a base code.

## Schema Architecture Option
### Option 1
![](image/schema-1.png)

### Option 2
![](image/schema-2.png)

## Component

## Installation
### MCP Client in Schema Option 1

1. First, you need to make sure that Docker is already installed in your node.

2. Than, we need to deploy `open-webui` and `ollama` container using below docker compose file.

```bash
services:
  ollama:
    image: ollama/ollama:latest
    ports:
      - 11434:11434
    volumes:
      - ollama:/root/.ollama
    container_name: ollama
    tty: true
    restart: unless-stopped

  open-webui:
    image: ghcr.io/open-webui/open-webui:main
    container_name: open-webui
    volumes:
      - open-webui:/app/backend/data
    depends_on:
      - ollama
    ports:
      - 3000:8080
    environment:
      - 'OLLAMA_BASE_URL=http://ollama:11434'
      - 'WEBUI_SECRET_KEY=your_secret_key'
    extra_hosts:
      - host.docker.internal:host-gateway
    restart: unless-stopped

volumes:
  ollama: {}
  open-webui: {}
```

3. Deploy `ollama` and `open-webui`
```bash
docker compose up -d
```

4. Downloading `gpt model` in `ollama`

```bash
docker exec -it ollama sh
ollama pull gpt-oss:20b
```

5. Ensure that gpt model has been able to use in `open-webui`

6. Back to the node and install `mcpo` to providing proxy for MCP Access on Open-WebUI

```bash
sudo snap install --classic astral-uv
uv install mcpo
```

7. Run `mcpo` (in my case, I'm using port 8000) and also pointing it into existing `mcp client` script

```bash
mcpo --host 0.0.0.0 --port 8000 -- python3 mcp-client.py --server "http://<server-node-ip>:8888"
```

8. Check if the MCP Client has been able to use by accessing `openapi.json`. If it reply with json reply that listing every tools than it is success, if not it is failed.

```bash
curl localhost:8000/openapi.json
```

9. Back to the 

### MCP Client in Schme Option 2


### MCP Server
```bash
# Clone the repository
git clone https://github.com/aldialvayadi2/simple-tools-security-scanner-kubernetes.git

cd simple-tools-security-scanner-kubernetes

# Create virtual environment
python3 -m venv my-venv
source my-venv/bin/activate

# Installing required Python dependencies
pip3 install -r requirements-mcp-server.txt
```
