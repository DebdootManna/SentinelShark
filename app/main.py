import sys
import asyncio
from PyQt6.QtWidgets import QApplication
from qasync import QEventLoop

from app.config import config
from app.services.queuemanager import queue_manager
from app.ui.mainwindow import MainWindow


def main():
    """Application entrypoint with qasync event loop integration."""
    if sys.platform == "win32":
        # On Windows, set SelectorEventLoopPolicy for robust qasync & httpx socket I/O compatibility
        try:
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        except Exception as e:
            print(f"[Main] Warning setting WindowsSelectorEventLoopPolicy: {e}")

    app = QApplication(sys.argv)
    app.setApplicationName("SentinelShark NIDS")

    # Set up qasync event loop for PyQt6 + asyncio non-blocking I/O
    loop = QEventLoop(app)
    asyncio.set_event_loop(loop)

    # Start main window
    window = MainWindow()
    window.show()

    # Start background Threat Intel Queue worker
    loop.create_task(queue_manager.start())

    # Run loop
    try:
        with loop:
            loop.run_forever()
    except Exception as e:
        print(f"[SentinelShark] Event loop exited: {e}")
    finally:
        loop.run_until_complete(queue_manager.stop())


if __name__ == "__main__":
    main()
