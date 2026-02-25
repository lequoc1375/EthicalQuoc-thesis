import argparse
from Scanner.scanner import scan_url
from Scanner.har_loader import parse_har
VERSION = "2025.1.0.0"
def main():
    parse = argparse.ArgumentParser(prog="ethicalQuoc", description="Insecure deserialization detection tool")
    
    parse.add_argument("--setup", action="store_true", help="Set up tool")
    parse.add_argument("--version", action="store_true", help="Show version")
    parse.add_argument("--update", action="store_true", help="Update tool")

    io_parse = argparse.ArgumentParser(add_help=False)
    io_parse.add_argument("-o", "--output", type=str, help="Export json file")
    io_parse.add_argument("-i", "--input", type=str, help="Input json file")
    
    o_parse = argparse.ArgumentParser(add_help=False)
    o_parse.add_argument("-o", "--output", type=str, help="Export json file")
    
    subparse = parse.add_subparsers(dest= "command", required=False)
    
    scan_command = subparse.add_parser("scan",parents=[o_parse], help="Scan target")
    scan_command.add_argument("--url", type=str, help="Scan website")
    scan_command.add_argument("--file", type=str, help="Scan file")
    scan_command.add_argument("--lab-mode", type=str, help="Enable lab mode")
    scan_command.add_argument("--har", type=str, help="Input har file ")
    choices = ["params","body","cookies","headers"]
    scan_command.add_argument("--scope", choices=choices,help="Advanced mode")
 
    analyze_cmd = subparse.add_parser("analyze", parents=[io_parse], help="Analyze & detect target input")

    assess_cmd = subparse.add_parser("assess", parents=[io_parse],help="Decision & risk assessment")
    
    report_cmd = subparse.add_parser("report",parents=[io_parse], help="Generate report")
    report_cmd.add_argument("--format",choices=["json", "pdf", "html"],default="json",help="Output report format")
    
    
    args = parse.parse_args()
    handle_arg(args)
    
def handle_arg(args):
    if args.setup:
        print("[*] Initializing environment...")
        return

    if args.version:
        print(f"EthicalQuoc version {VERSION}")
        return

    if args.update:
        print("[*] Updating EthicalQuoc...")
        return

    if not args.command:
        print("[!] No command specified. Use -h for help.")
        return

    if args.command == "scan":
        if not args.url and not args.file and not args.har:
            print("[!] Error: Please provide --url or --file or --har to start scanning.")
            return
        if args.url:
            scan_url(
                url=args.url,
                scope=args.scope,
                output_file=args.output,
                session_cookie=args.lab_mode
            )
        if args.har:
            parse_har(
                file_path = args.har,
            )
            

    elif args.command == "analyze":
        if not args.input:
            print("[!] Error: analyze requires -i/--input file.")
            return
        print(f"[*] Analyzing: {args.input}")

    elif args.command == "assess":
        print(f"[*] Assessing Risk for: {args.input}")

    elif args.command == "report":
        print(f"[*] Generating {args.format.upper()} report from {args.input}...")

if __name__ == "__main__":
    main()