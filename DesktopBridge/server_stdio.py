from server import server
from desktop_lifecycle import register_host


if __name__ == "__main__":
    register_host()
    server.run(transport="stdio")
