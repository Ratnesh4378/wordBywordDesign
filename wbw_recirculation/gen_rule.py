import argparse

def convert_to_hex(strings, max_key_size):
    """
    Convert strings of the format XXXXXX:YYYYYY into hexadecimal forms, dividing into stages based on max_key_size.
    
    :param strings: List of strings in the format XXXXXX:YYYYYY,
    :param max_key_size: Maximum key size in bytes.
    :return: List of hexadecimal strings for each stage.
    """
    stages=max_key_size//4
    output=[]

    for s in strings:
        curr_len=0
        hexValues=[]
        words=s.split(':')
        words[0]+=':'
        for i in range(stages-1):
            hexValues.append("0x0")
        hexValues.append("0x0")
        hexValues.append("0x0")
        hexValues.append("0x0")

        for i in range(stages-1):
            hexValues.append("0x0")
        hexValues.append("0x0")
        hexValues.append("0x0")
        hexValues.append("0x0")
        for i in range(stages):
            if curr_len == len(words[0])-1:
                chunk=words[0][curr_len:curr_len+1]
                hex_chunk = '0x' + ''.join(format(ord(char), '02x') for char in chunk)
                hexValues[stages+1]=hex_chunk
                break
            elif curr_len+1 == len(words[0])-1:
                # chunk=words[0][curr_len:curr_len+2] 
                # hex_chunk = '0x' + ''.join(format(ord(char), '02x') for char in chunk)
                # hexValues[stages]=hex_chunk
                #  Jugaad The last two bytes are not getting extracted properly
                break
            elif curr_len+2 == len(words[0])-1:
                chunk=words[0][curr_len:curr_len+1]
                hex_chunk = '0x' + ''.join(format(ord(char), '02x') for char in chunk)
                hexValues[stages+1]=hex_chunk
                # ********
                # chunk=words[0][curr_len+1:curr_len+3]
                # hex_chunk = '0x' + ''.join(format(ord(char), '02x') for char in chunk)
                # hexValues[stages]=hex_chunk
                # Jugaad , problem with extracting the last two bytes
                break

            elif curr_len+3 == len(words[0])-1:
                # chunk=words[0][curr_len:curr_len+4]
                # hex_chunk = '0x' + ''.join(format(ord(char), '02x') for char in chunk)
                # hexValues[stages-1]=hex_chunk
                # jugaad goes from here
                chunk=words[0][curr_len+2:curr_len+4]
                hex_chunk = '0x' + ''.join(format(ord(char), '02x') for char in chunk)
                hexValues[stages-1]=hex_chunk
                break
            else:
                chunk = words[0][curr_len:curr_len + 4]
                hex_chunk = '0x' + ''.join(format(ord(char), '02x') for char in chunk)
                hexValues[i]=hex_chunk
                curr_len+=4
        curr_len=0
        idx=stages+2
        for i in range(stages):
            if curr_len ==len(words[1])-1:
                chunk=words[1][curr_len:curr_len+1]
                hex_chunk = '0x' + ''.join(format(ord(char), '02x') for char in chunk)
                hexValues[idx+stages+1]=hex_chunk
                break
            elif curr_len+1 == len(words[1])-1:
                # *********
                # chunk=words[1][curr_len:curr_len+2]
                # hex_chunk = '0x' + ''.join(format(ord(char), '02x') for char in chunk)
                # hexValues[idx+stages]=hex_chunk
                # Jugaad 
                break
            elif curr_len+2 == len(words[1])-1:
                chunk=words[1][curr_len:curr_len+1]
                hex_chunk = '0x' + ''.join(format(ord(char), '02x') for char in chunk)
                hexValues[idx+stages+1]=hex_chunk
                # *******
                # chunk=words[1][curr_len+1:curr_len+3]
                # hex_chunk = '0x' + ''.join(format(ord(char), '02x') for char in chunk)
                # hexValues[idx+stages]=hex_chunk
                # Jugaad
                break
            elif curr_len+3 == len(words[1])-1:
                # chunk=words[1][curr_len:curr_len+4]
                # hex_chunk = '0x' + ''.join(format(ord(char), '02x') for char in chunk)
                # hexValues[idx+stages-1]=hex_chunk
                # Jugaad goes from here,
                chunk=words[1][curr_len+2:curr_len+4]
                hex_chunk = '0x' + ''.join(format(ord(char), '02x') for char in chunk)
                hexValues[idx+stages-1]=hex_chunk
                break
            else:
                chunk=words[1][curr_len:curr_len+4]
                hex_chunk = '0x' + ''.join(format(ord(char), '02x') for char in chunk)
                hexValues[idx+i]=hex_chunk
                curr_len+=4
        output.append(hexValues)
    return output

def save_to_file(converted_hexes, output_file,num_keys, num_stages):
    """
    Save the converted hexadecimal stages to a file.

    :param converted_hexes: List of hexadecimal stages for each string.
    :param output_file: File path to save the hexadecimal values.
    """
    with open(output_file, "w") as file:
        rules="""
# Mirror Rules
bfrt.mirror.cfg.add_with_normal(sid=1, direction="INGRESS", ucast_egress_port = 64, ucast_egress_port_valid = True, session_enable = True)
bfrt.mirror.cfg.add_with_normal(sid=2, direction="INGRESS", ucast_egress_port = 65, ucast_egress_port_valid = True, session_enable = True)

# Recirculate, mirror and forwarding set up rules
bfrt.temp.pipe.IngressControl.t_setup_mirror_rclt.add_with_a_setup_mirror_rclt("192.168.1.1", 2, 68)
bfrt.temp.pipe.IngressControl.t_setup_mirror_rclt.add_with_a_setup_mirror_rclt("192.168.1.2", 1, 68)

bfrt.temp.pipe.IngressControl.t_save_state_and_recirculate.add_with_a_save_state_and_recirculate(0, 0, 1000, 68)

bfrt.temp.pipe.IngressControl.t_arp.add_with_a_arp("192.168.1.1", "7a:5b:35:84:ee:58")
bfrt.temp.pipe.IngressControl.t_arp.add_with_a_arp("192.168.1.2", "02:b5:24:d8:2a:58")
"""
        file.write(rules)
        for i in range(num_keys):
            for j in range(num_stages):
                string="bfrt.temp.pipe.IngressControl.t_filter_"+str(i)+"_"+str(j)+".add_with_a_filter_"+str(i)+"_"+str(j)+"("
                string += ", ".join(converted_hexes[i])
                string += ")\n"
                file.write(string)
        string="bfrt.temp.pipe.IngressControl.t_check.add_with_a_increase_counter("
        values=[]
        for i in range(num_keys):
            values.append("1")
        string+=", ".join(values)
        string+=")\n"
        file.write(string)
        rules="""

# bfrt.temp.pipe.IngressControl.rclt_tot_cnt.get(0, from_hw=1)
# bfrt.temp.pipe.IngressControl.c_tot_cnt.get(0, from_hw=1)

bfrt.temp.pipe.IngressControl.c_tot_cnt.clear()
bfrt.temp.pipe.IngressControl.rclt_tot_cnt.clear()
"""
        file.write(rules)

    #bfrt.temp.pipe.IngressControl.t_check.add_with_a_increase_counter(1,1)

def main():
    parser = argparse.ArgumentParser(description="Convert strings of the format XXXXXX:YYYYYY to hexadecimal stages.")
    parser.add_argument("--strings", nargs="+", required=True, help="List of strings to convert, formatted as XXXXXX:YYYYYY,")
    parser.add_argument("--max_key_size", type=int, required=True, help="Maximum key size in bytes.")
    parser.add_argument("--output_file", type=str, required=True, help="File path to save the converted hexadecimal values.")
    parser.add_argument("--num_keys", type=int, required=True, help="Number of keys.")
    parser.add_argument("--num_stages", type=int, required=True, help="Number of stages.")

    args = parser.parse_args()

    converted_hexes = convert_to_hex(args.strings, args.max_key_size)

    save_to_file(converted_hexes, args.output_file, args.num_keys,args.num_stages)
    print(f"Hexadecimal values saved to {args.output_file}")

if __name__ == "__main__":
    main()
