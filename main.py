# main.py
import tkinter as tk
from encryption_interface import EncryptionInterface

if __name__ == "__main__":
    root = tk.Tk()
    interface = EncryptionInterface(root)
    root.mainloop()
