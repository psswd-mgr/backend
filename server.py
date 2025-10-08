import asyncio
import json
import websockets
from vault import Vault  # tu clase Vault
import os

# Ruta del archivo de metadatos
METADATA_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "metadata.json")

# Diccionario de sesiones por conexión
sessions = {}

async def handle_client(websocket):
    vault_instance = None
    try:
        async for message in websocket:
            try:
                data = json.loads(message)
                action = data.get("action")
                
                if action == "auth":
                    print("Authenticating...")
                    password = data.get("password")
                    if not password:
                        await websocket.send(json.dumps({"status": "error", "message": "Password required"}))
                        continue

                    vault_instance = Vault()
                    try:
                        result = vault_instance.load_vault(password, METADATA_PATH)
                        if result == 0:
                            msg = "Vault created successfully."
                        else:
                            msg = "Authenticated successfully."
                        sessions[websocket] = vault_instance
                        await websocket.send(json.dumps({"status": "ok", "message": msg}))
                    except ValueError:
                        await websocket.send(json.dumps({"status": "error", "message": "Incorrect password"}))

                elif action == "read":
                    vault_instance = sessions.get(websocket)
                    if not vault_instance or not vault_instance.session:
                        await websocket.send(json.dumps({"status": "error", "message": "Not authenticated"}))
                        continue

                    try:
                        content = vault_instance.read_file()
                        try:
                            parsed = json.loads(content)
                            await websocket.send(json.dumps({"status": "ok", "data": parsed}))
                        except Exception:
                            await websocket.send(json.dumps({"status": "ok", "data": content}))
                    except Exception as e:
                        await websocket.send(json.dumps({"status": "error", "message": str(e)}))

                elif action == "save":
                    vault_instance = sessions.get(websocket)
                    if not vault_instance or not vault_instance.session:
                        await websocket.send(json.dumps({"status": "error", "message": "Not authenticated"}))
                        continue
                    content = json.dumps(data.get("data", ""))
                    try:
                        vault_instance.save_file(content)
                        await websocket.send(json.dumps({"status": "ok", "message": "File saved"}))
                    except Exception as e:
                        await websocket.send(json.dumps({"status": "error", "message": str(e)}))

                elif action == "end":
                    vault_instance = sessions.get(websocket)
                    if vault_instance:
                        vault_instance.end_session()
                        del sessions[websocket]
                    await websocket.send(json.dumps({"status": "ok", "message": "Session ended"}))

                else:
                    await websocket.send(json.dumps({"status": "error", "message": "Unknown action"}))
            
            except json.JSONDecodeError:
                await websocket.send(json.dumps({"status": "error", "message": "Invalid JSON"}))
            
    except Exception as e:
        print(f"Error: {e}")    

    except websockets.ConnectionClosed:
        if websocket in sessions:
            del sessions[websocket]
        print("Connection closed")

async def main():
    async with websockets.serve(handle_client, "0.0.0.0", 8765):
        print("WebSocket server running on ws://0.0.0.0:8765")
        await asyncio.Future()

if __name__ == "__main__":
    asyncio.run(main())
