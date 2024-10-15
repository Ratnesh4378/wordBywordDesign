import json
import sys
import subprocess

key_val_cnt=0
find_filter_table={}
find_extract_list=[]
find_extract_action={}
map_index=-1
map_update=""





def save_rule_to_file(filename, rule):
    with open(filename, 'w') as file:
        file.write(rule)
    print(f"rules saved to {filename}")



class OperationNode:
    def __init__(self, op_type, args, index):
        self.op_type = op_type
        self.args = args
        self.index = index
        self.next_node = None

    def __repr__(self):
        return f"OperationNode(type={self.op_type}, args={self.args}, index={self.index})"

def build_operation_tree(ir_data):
    nodes = []

    for index, operation in enumerate(ir_data):
        nodes.append(OperationNode(op_type=operation["type"], args=operation["args"], index=index))

    for index, operation in enumerate(ir_data):
        if "next" in operation:
            next_index = operation["next"]
            if isinstance(next_index, str) and next_index.isdigit(): 
                next_index = int(next_index)  # Convert to integer index
            # if isinstance(next_index, int): 
            #     # if next_index > 0:
            #     #     next_index -= 1

            if 0 <= next_index < len(nodes):
                nodes[index].next_node = nodes[next_index]

    return nodes[0] if nodes else None


def modify_ir(ir_data):
    index=0
    for dict in ir_data:
        dict["index"]=index
        dict["done"]=False
        dict["nextIndex"]=dict["next"]
        index+=1
    
    return ir_data

def build_map(ir_data):
    index_map={}
    for dict in ir_data:
        index_map[dict["index"]]=dict
    
    return index_map

def process_find(index_map, index):
    # for find:  "args": ["offset", "match_size", "match_pattern", "action count", "action-index-1", ......],
    # for filter: "args": ["offset","size","match_value"],
    action_cnt=int(index_map[index]["args"][3])
    matchPattern=index_map[index]["args"][2]
    global map_index
    global map_update
    find_filter=""
    # possible actions: "filter, extract"
    for action in range(4,4+action_cnt):
        actionIndex=int(index_map[index]["args"][action])
        if index_map[actionIndex]["type"]=="Filter":
            find_filter=matchPattern+":"+index_map[actionIndex]["args"][2]
            find_filter_table[matchPattern]=index_map[actionIndex]["args"][2]
            index_map[actionIndex]["done"]=True
        elif index_map[actionIndex]["type"]=="Extract":
            find_extract_list.append(matchPattern)
            action_index=int(index_map[actionIndex]["args"][4])
            if index_map[action_index]["type"]=="Map_Update":
                map_index=int(index_map[actionIndex]["args"][5])
                map_update=matchPattern
            index_map[actionIndex]["done"]=True
    # print(action_cnt)
    return matchPattern


def main():
    if len(sys.argv) != 2:
        print("Usage: python wBwCompiler.py <path_to_ir_json_file>")
        sys.exit(1)

    ir_file_path = sys.argv[1]

    with open(ir_file_path, 'r') as f:
        ir_data = json.load(f)

    ir_data=modify_ir(ir_data)
    index_map=build_map(ir_data)

    for i in range(4):
        index_map[i]["done"]=True
    
    fixed_parse=index_map[3]["args"][2]
    fixed_parse_len=len(fixed_parse)

    prev=""
    countOp=[]
    sumOp=[]
    # map_update=[]
    # map_index=-1
    for index in index_map:
        if index_map[index]["done"]:
            continue
        if(index_map[index]["type"]=="Find"):
            prev="Find"
            matchPattern=process_find(index_map,index)
        elif prev=="Find" and index_map[index]["type"]=="Count":
            countOp.append(matchPattern)
        elif prev=="Find" and index_map[index]["type"]=="Sum":
            sumOp.append(matchPattern)
        # elif prev=="Find" and index_map[index]["type"]=="Map_Update":
        #     map_update.append({matchPattern,index_map[index]["args"][2]})
        # print(index_map[index])
    
    # bfrt.grpa.pipe.IngressControl.t_fixed_parse.add_with_a_fixed_parse(0x6164646974656d2f,0x63617274,0x2c)


    no_of_key_val_pairs=len(find_extract_list)+len(find_filter_table)

    # print(no_of_key_val_pairs)
    # print(fixed_parse_len)
    count=0
    if(len(countOp)>0):
        count=1
    no_of_filters=len(find_filter_table)
    no_of_extracts=len(find_extract_list)
    isSum=len(sumOp)

    fixed_parse_key=fixed_parse+","
    fixed_parse_powers=[]
    powers=[256,128,64,32,16,8,2,1]
    fixed_parse_bits=len(fixed_parse_key)*8
    for power in powers:
        if fixed_parse_bits >= power:
            fixed_parse_powers.append(power)
            fixed_parse_bits -= power
    fixed_parse_table=[]
    

    current_index = 0
    for power in fixed_parse_powers:
        num_bytes = power // 8
        segment = fixed_parse_key[current_index:current_index + num_bytes]
        segment_hex = '0x'+''.join(format(ord(char), '02x') for char in segment)
        fixed_parse_table.append(segment_hex)
        current_index += num_bytes


    fixed_parse_rule="bfrt.grpa.pipe.IngressControl.t_fixed_parse.add_with_a_fixed_parse("
    for seg in fixed_parse_table:
        fixed_parse_rule+=seg+','
    fixed_parse_rule=fixed_parse_rule.rstrip(fixed_parse_rule[-1])
    fixed_parse_rule+=")"


    filter_key_val_pairs=[]
    extract_key=[]
    for key in find_filter_table:
        val=find_filter_table[key]
        key_dict={"first":"0x0",
            "second":"0x0",
            "third":"0x0",
            "fourth":"0x0",
            "fifth":"0x0",
            "sixth":"0x0",
            "l4":"0x0",
            "l2":"0x0",
            "l1":"0x0"
        }
        chunk_list=["first","second","third","fourth","fifth","sixth"]
        current_index=0
        for i in range(0,len(key),4):
            if(i+4<len(key)):
                chunk = key[i:i + 4]
                hex_chunk = '0x' + ''.join(format(ord(char), '02x') for char in chunk)
                key_dict[chunk_list[current_index]]=hex_chunk
                current_index+=1
            if (i+4==len(key)):
                chunk = key[i:i + 4]
                hex_chunk = '0x' + ''.join(format(ord(char), '02x') for char in chunk)
                key_dict["l4"]=hex_chunk
            elif (i+3==len(key)):
                chunk=key[i:i+2]
                print(chunk)
                hex_chunk = '0x' + ''.join(format(ord(char), '02x') for char in chunk)
                key_dict["l2"]=hex_chunk
                chunk=key[i+2:i+3]
                hex_chunk = '0x' + ''.join(format(ord(char), '02x') for char in chunk)
                key_dict["l1"]=hex_chunk
            elif (i+2==len(key)):
                chunk=key[i:i+2]
                hex_chunk = '0x' + ''.join(format(ord(char), '02x') for char in chunk)
                key_dict["l2"]=hex_chunk
            elif (i+1==(len(key))):
                chunk=key[i:i+1]
                hex_chunk = '0x' + ''.join(format(ord(char), '02x') for char in chunk)
                key_dict["l1"]=hex_chunk
        val_dict={"first":"0x0",
            "second":"0x0",
            "third":"0x0",
            "fourth":"0x0",
            "fifth":"0x0",
            "sixth":"0x0",
            "l4":"0x0",
            "l2":"0x0",
            "l1":"0x0"
        }

        current_index=0
        for i in range(0,len(val),4):
            if(i+4<(len(val))):
                chunk=val[i:i+4]
                hex_chunk= '0x' + ''.join(format(ord(char), '02x') for char in chunk)
                val_dict[chunk_list[current_index]]=hex_chunk
                current_index+=1
            if(i+4==len(val)):
                chunk = val[i:i + 4]
                hex_chunk = '0x' + ''.join(format(ord(char), '02x') for char in chunk)
                val_dict["l4"]=hex_chunk
            elif (i+3==len(val)):
                chunk=val[i:i+2]
                hex_chunk = '0x' + ''.join(format(ord(char), '02x') for char in chunk)
                val_dict["l2"]=hex_chunk
                chunk=val[i+2:i+3]
                hex_chunk = '0x' + ''.join(format(ord(char), '02x') for char in chunk)
                val_dict["l1"]=hex_chunk
            elif (i+2==len(val)):
                chunk=val[i:i+2]
                hex_chunk = '0x' + ''.join(format(ord(char), '02x') for char in chunk)
                val_dict["l2"]=hex_chunk
            elif (i+1==(len(val))):
                chunk=val[i:i+1]
                hex_chunk = '0x' + ''.join(format(ord(char), '02x') for char in chunk)
                val_dict["l1"]=hex_chunk
        filter_key_val_pairs.append([key_dict,val_dict])

    
    for key in find_extract_list:
        key_dict={"first":"0x0",
            "second":"0x0",
            "third":"0x0",
            "fourth":"0x0",
            "fifth":"0x0",
            "sixth":"0x0",
            "l4":"0x0",
            "l2":"0x0",
            "l1":"0x0"
        }
        chunk_list=["first","second","third","fourth","fifth","sixth"]
        current_index=0
        for i in range(0,len(key),4):
            if(i+4<len(key)):
                chunk = key[i:i + 4]
                hex_chunk = '0x' + ''.join(format(ord(char), '02x') for char in chunk)
                key_dict[chunk_list[current_index]]=hex_chunk
                current_index+=1
            if (i+4==len(key)):
                chunk = key[i:i + 4]
                hex_chunk = '0x' + ''.join(format(ord(char), '02x') for char in chunk)
                key_dict["l4"]=hex_chunk
            elif (i+3==len(key)):
                chunk=key[i:i+2]
                hex_chunk = '0x' + ''.join(format(ord(char), '02x') for char in chunk)
                key_dict["l2"]=hex_chunk
                chunk=key[i+2:i+3]
                hex_chunk = '0x' + ''.join(format(ord(char), '02x') for char in chunk)
                key_dict["l1"]=hex_chunk
            elif (i+2==len(key)):
                chunk=key[i:i+2]
                hex_chunk = '0x' + ''.join(format(ord(char), '02x') for char in chunk)
                key_dict["l2"]=hex_chunk
            elif (i+1==(len(key))):
                chunk=key[i:i+1]
                hex_chunk = '0x' + ''.join(format(ord(char), '02x') for char in chunk)
                key_dict["l1"]=hex_chunk
        extract_key.append(key_dict)

    filter_table_rule=[]
    for i in range(no_of_filters):
        rule=""
        for j in range(no_of_key_val_pairs):
            rule="bfrt.grpa.pipe.IngressControl.t_filter_"
            rule+=str(i)+"_"+str(j)+".add_with_a_filter_"+str(i)+"_"+str(j)+"("
            for dict in filter_key_val_pairs[i]:
                for key in dict:
                    rule+=dict[key]+","
            rule=rule.rstrip(rule[-1])
            rule+=" )"
            filter_table_rule.append(rule)
        
        
    extract_table_rule=[]
    for i in range(no_of_extracts):
        rule=""
        for j in range(no_of_key_val_pairs):
            rule="bfrt.grpa.pipe.IngressControl.t_extract_"+str(i)+"_"+str(j)+".add_with_a_extract_"+str(i)+"_"+str(j)+"("
            for key in extract_key[i]:
                rule+=extract_key[i][key]+","
            rule=rule.rstrip(rule[-1])
            rule+=")"
            extract_table_rule.append(rule)
    

    all_rules=""

    all_rules+="bfrt.grpa.pipe.IngressControl.t_arp.add_with_a_arp(\"192.168.0.1\", \"7a:5b:35:84:ee:58\")\n"
    all_rules+="bfrt.grpa.pipe.IngressControl.t_arp.add_with_a_arp(\"192.168.0.2\", \"02:b5:24:d8:2a:58\")\n"
    all_rules+="bfrt.grpa.pipe.IngressControl.t_forward.add_with_a_forward(\"192.168.0.2\", 1)\n"
    all_rules+=fixed_parse_rule+"\n"
    for rule in filter_table_rule:
        all_rules+=rule+"\n"
    for rule in extract_table_rule:
        all_rules+=rule+"\n"
    
    map_index_key=""
    map_index_val=""

    if map_index!=-1:
        if index_map[int(index_map[map_index]["args"][4])]["type"]=="Filter":
            cnt=0
            for index in index_map:
                if index_map[index]["index"]==map_index:
                    break
                if index_map[index]["type"]=="Filter":
                    cnt+=1
            map_index_key="filterVal_"+str(cnt)
        elif index_map[int(index_map[map_index]["args"][4])]["type"]=="Extract":
            cnt=0
            for index in index_map:
                if index_map[index]["index"]==map_index:
                    break
                if index_map[index]["type"]=="Extract":
                    cnt+=1
            map_index_key="extractVal_"+str(cnt)

        found=0
        cnt=0
        for key in find_filter_table:
            if key==map_update:
                found=1
                break
            cnt+=1
        if found==1:
            map_index_val="filterVal_"+str(cnt)
        else:
            found=0
            cnt=0
            for key in find_extract_list:
                if key==map_update:
                    found=1
                    break
                cnt+=1
            map_index_val="extractVal_"+str(cnt)
        
    

    

    json_filename=sys.argv[1].split(".")
    save_rule_to_file(f"{json_filename[0]}_rule.py",all_rules)   

    print(map_index_key,map_index_val)
    

        
    subprocess.run(["python3", "auto_gen_util.py",str(no_of_key_val_pairs),str(32),str(fixed_parse_len+1),str(no_of_filters),str(count),str(no_of_extracts), str(isSum),map_index_key,map_index_val,str(json_filename[0])])

    # for dict in ir_data:
    #     print("Dict data")
    #     for key in dict:
    #         print(key,dict[key])
        

    # root_node = build_operation_tree(ir_data)

    # print("Complete Operation Tree:")
    # print_tree(root_node)

if __name__ == "__main__":
    main()
