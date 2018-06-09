import re
import os

def del_comments(in_file, t_file):
  for line in in_file:
    line = line.lstrip()
    line = line.expandtabs(1)
    if ";" in line:
      new_line = re.split(r';', line)      
      del new_line[1]
      new_line = ' '.join(new_line)
      t_file.write(new_line + '\n')   
    else:
      t_file.write(line)

def loc_addr(line):
  if "loc_" in line:
      if re.match(r'loc_', line):
        new_line = "loc_addr:"
        output_file.write(new_line + '\n')
      else:
        new_line = re.split(r'_', line, maxsplit=1)
        new_line[1] = "addr"
        new_line = '_'.join(new_line)
        output_file.write(new_line + '\n')
      return True
  else:
    return False  

def call_func (line):
  if "call" in line:       
    new_line = "call func"          
    output_file.write(new_line + '\n')
    return True
  else:
    return False  

def check_operand (operand):
  if re.fullmatch(r'\d+|[0-9a-fA-F]+h', operand):     
      if '[' and ']' in operand:
        new_operand = 'operand'        
      else:
        new_operand = operand
  else:
    new_operand = 'operand'  
  return new_operand    

def operand (line):
  new_line = re.split(r'\s+', line)  
  simpl_line = new_line.pop(0)  
  new_line = ''.join(new_line) 
  new_line = re.split(r',', new_line)   
  for item in new_line:
    if item != '':
      simpl_line = simpl_line + ' ' + check_operand (item) + ','
  output_file.write(simpl_line[:len(simpl_line)-1] + '\n')

def t_filename(input_f):
  temp_filename = 't_'+ input_filename[:len(input_filename)-4] + '_normalized.txt'
  return temp_filename

def out_filename(input_f):
  output_filename = input_filename[:len(input_filename)-4] + '_normalized.txt'
  return output_filename
  
print("Input filename:")
input_filename = input()

input_file = open(input_filename, 'r')
temp_file = open(t_filename(input_filename),'w')
output_file = open(out_filename(input_filename),'w')
del_comments(input_file, temp_file)
temp_file.close()

temp_file = open(t_filename(input_filename),'r')

for line in temp_file:
  if loc_addr(line) == True:
    continue       
  elif call_func(line) == True:
    continue 
  elif "end" in line or "proc" in line:
    output_file.write(line)     
  elif "=" in line:
    output_file.write(line)
  else:
    operand (line)     

input_file.close()
output_file.close()
temp_file.close()
os.remove(t_filename(input_filename)) 
