from typing import Callable
from sniffer.sniffer import Sniffer, Process
from sniffer.sniffer_types import Ethernet, Ip, Tcp

from prompt_toolkit import print_formatted_text
from prompt_toolkit.patch_stdout import patch_stdout
from prompt_toolkit.shortcuts import PromptSession
from prompt_toolkit.formatted_text import FormattedText, fragment_list_to_text, to_formatted_text
from prompt_toolkit.output import ColorDepth

import threading
import asyncio

def print_color(r, g, b, text):
    """
    Print text in specified RGB color.
    """
    color_code = f"\033[38;2;{r};{g};{b}m"
    reset_code = "\033[0m"
    
    return f"{color_code}{text}{reset_code}"

def prepare_terminal_screen():
    print(print_color(154, 213, 202, """
         _______     _______          _____  
        |  __ \ \   / / ____|   /\   |  __ \ 
        | |__) \ \_/ / |       /  \  | |__) |
        |  ___/ \   /| |      / /\ \ |  ___/ 
        | |      | | | |____ / ____ \| |     
        |_|      |_|  \_____/_/    \_\_|     
    """))

    print(print_color(53, 144, 243, "\n| Welcome to Pycap"))
    print(print_color(53, 144, 243, "| Version 0.0.1"))
    print(print_color(53, 144, 243, "| Have fun!"))

    print()

def callback(eth: Ethernet, ip: Ip, tcp: Tcp, data: bytes) -> None:
    print(eth.destination)

class ProcessManager:
    def __init__(self, processes: list[Process]) -> None:
        self.processes = processes
        
    def do_exit(self):
        for process in self.processes:
            process.stop()

        return True

    def on_input(self, inp: str) -> None:
        if inp == "exit":
            return self.do_exit()

        if inp == "list":
            print_formatted_text("")

            for process in self.processes:
                message = FormattedText([("fg:#efca08", process.name)])
                message.append(("fg:#ffffff", " > "))

                if process.running:
                    message.append(("fg:#41e2ba", "running"))
                else:
                    message.append(("fg:#f13030", "not running"))

                print_formatted_text(message, color_depth=ColorDepth.TRUE_COLOR)
                
            print_formatted_text("")

            return
        
        parts = inp.split(" ")

        if len(parts) < 2:
            return

        if parts[1] == "on":
            for process in self.processes:
                if process.name != parts[0]:
                    return

                if process.running == True:
                    return

                t = threading.Thread(target=process.start, daemon=True)
                t.start()
                
                return

        if parts[1] == "off":
            for process in self.processes:
                if process.name != parts[0]:
                    return

                if process.running == False:
                    return

                process.stop()
                
                return

async def interactive_shell(callback: Callable[[str], bool | None]):
    """
    Like `interactive_shell`, but doing things manual.
    """
    prefix = FormattedText([("fg:#41e2ba", ">>> ")])

    # Create Prompt.
    session = PromptSession(prefix)

    # Run echo loop. Read text from stdin, and reply it back.
    while True:
        try:
            inp = await session.prompt_async()
            result = callback(inp)

            if result:
                return

        except (EOFError, KeyboardInterrupt):
            return

async def main():
    prepare_terminal_screen()

    sniffer = Sniffer(80, callback)
    processes: list[Process] = [sniffer]
    
    with patch_stdout():
        manager = ProcessManager(processes)

        try:
            await interactive_shell(manager.on_input)
        finally:
            manager.do_exit()
        print("Quitting event loop")

if __name__ == "__main__":
    asyncio.run(main())