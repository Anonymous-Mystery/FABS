'''
:Date:            04/2025
'''

from charm.toolbox.pairinggroup import PairingGroup, G1, G2, GT, ZR
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.policytree import PolicyParser
from msp import MSP

from FABS_kp import FABS_KPABS
from FABS_sp import FABS_SPABS
from RD16_kp import RD16
from KCGD14_sp import KCGD14
import re, random, copy
import time

#--------------------------------------------------- Measure average time module ----------------------------------------------
def measure_average_times_kp(ABS, n, attr_list, attr_policy, msg, N=5):   
    sum_setup = 0
    sum_keygen = 0
    sum_sign = 0
    sum_verify = 0

    for i in range(N):
        # setup time
        start_setup = time.time()
        (mpk, msk) = ABS.setup(n)
        end_setup = time.time()
        time_setup = end_setup - start_setup
        sum_setup += time_setup

        # keygen time
        start_keygen = time.time()
        sk = ABS.keygen(mpk, msk, attr_policy)
        end_keygen = time.time()
        time_keygen = end_keygen - start_keygen
        sum_keygen += time_keygen

        # signing time
        start_sign = time.time()
        signature = ABS.sign(mpk, sk, msg, attr_policy, attr_list)
        end_sign = time.time()
        time_sign = end_sign - start_sign
        sum_sign += time_sign       

        # Verification time
        start_verify = time.time()
        result = ABS.verify(mpk, signature, attr_list, msg)
        end_verify = time.time()
        time_verify = end_verify - start_verify
        sum_verify += time_verify

    
    # compute average time
    time_setup = sum_setup / N
    time_keygen = sum_keygen / N
    time_sign = sum_sign / N
    time_verify = sum_verify / N

    return [time_setup, time_keygen, time_sign, time_verify]

def measure_average_times_sp(ABS, attr_universe, attr_list, attr_policy, msg, N=1):  
    sum_setup = 0
    sum_keygen = 0
    sum_sign = 0
    sum_verify = 0

    for i in range(N):
        # setup time
        start_setup = time.time()
        (mpk, msk) = ABS.setup(attr_universe)
        end_setup = time.time()
        time_setup = end_setup - start_setup
        sum_setup += time_setup

        # keygen time
        start_keygen = time.time()
        sk = ABS.keygen(mpk, msk, attr_list)
        end_keygen = time.time()
        time_keygen = end_keygen - start_keygen
        sum_keygen += time_keygen

        # signing time
        start_sign = time.time()
        signature = ABS.sign(mpk, sk, msg, attr_policy, attr_list)
        end_sign = time.time()
        time_sign = end_sign - start_sign
        sum_sign += time_sign       

        # Verification time
        start_verify = time.time()
        result = ABS.verify(mpk, signature, attr_policy, msg)
        end_verify = time.time()
        time_verify = end_verify - start_verify
        sum_verify += time_verify

    
    # compute average time
    time_setup = sum_setup / N
    time_keygen = sum_keygen / N
    time_sign = sum_sign / N
    time_verify = sum_verify / N

    return [time_setup, time_keygen, time_sign, time_verify]


#-------------------------------------------------- print running time module -------------------------------------------------
def print_running_time(scheme_name, times):
    record = ('{:<22}'.format(scheme_name) + format(times[0] * 1000, '7.2f') + '   ' + format(times[1] * 1000, '7.2f') + '   ' + format(times[2] * 1000, '7.2f') + '   ' + format(times[3] * 1000, '7.2f') )
    print(record)
    return record    
    
#-------------------------------------------------- run all module ------------------------------------------------------------
def run_kp(pairing_group, n, attr_list, policy_str, msg):  
    fabs_kpabs = FABS_KPABS(pairing_group)
    fabs_kpabs_time = measure_average_times_kp(fabs_kpabs, n, attr_list, policy_str, msg)
    
    rd16_kpabs = RD16(pairing_group)
    rd16_kpabs_time = measure_average_times_kp(rd16_kpabs, n, attr_list, policy_str, msg)
                          
    n1, n2, m, i = get_par(pairing_group, policy_str, attr_list)
    print('\n')
    print('*'*70)
    print('Running times (ms) curve BN254: n1={}  n2={}  m={}  i={}'.format(n1, n2, m, i))
    print('*'*70)
    algos = ['Setup', 'KeyGen', 'Sign', 'Verify']   
    algo_string = 'Scheme {:<15}'.format('') + '  ' + algos[0] + '    ' + algos[1] + '     ' + algos[2] + '     ' + algos[3]
    print('-'*70)
    print(algo_string)
    print('-'*70)
    record1 = print_running_time(fabs_kpabs.name, fabs_kpabs_time)      
    record2 = print_running_time(rd16_kpabs.name, rd16_kpabs_time)
    print('-'*70)          
   
    with open('Results/BN254.txt', 'a') as f:
        f.write('Scheme: ' + 'Running times (ms) curve BN254: n1={}  n2={}  m={}  i={}'.format(n1, n2, m, i) + '\n')
        f.write(algo_string + '\n')
        f.write(record1 + '\n')     
        f.write(record2 + '\n')  
        f.write('\n')     
    open('Results/BN254.txt', 'r')  
    with open('Results/BN254.txt', 'a') as f:     
        f.write('*' * 70 + '\n')            
    return       

#-------------------------------------------------- run all module ------------------------------------------------------------
def run_sp(pairing_group, attr_universe, attr_list, policy_str, msg):  
    fabs_spabs = FABS_SPABS(pairing_group)
    fabs_spabs_time = measure_average_times_sp(fabs_spabs, attr_universe, attr_list, policy_str, msg)
    
    kcgd14_spabs = KCGD14(pairing_group)
    kcgd14_spabs_time = measure_average_times_sp(kcgd14_spabs, attr_universe, attr_list, policy_str, msg)
                          
    n1, n2, m, i = get_par(pairing_group, policy_str, attr_list)
    print('\n')
    print('*'*70)
    print('Running times (ms) curve BN254: n1={}  n2={}  m={}  i={}'.format(n1, n2, m, i))
    print('*'*70)
    algos = ['Setup', 'KeyGen', 'Sign', 'Verify']   
    algo_string = 'Scheme {:<15}'.format('') + '  ' + algos[0] + '    ' + algos[1] + '     ' + algos[2] + '     ' + algos[3]
    print('-'*70)
    print(algo_string)
    print('-'*70)
    record1 = print_running_time(fabs_spabs.name, fabs_spabs_time)     
    record2 = print_running_time(kcgd14_spabs.name, kcgd14_spabs_time)
    print('-'*70)          
   
    with open('Results/BN254.txt', 'a') as f:
        f.write('Scheme: ' + 'Running times (ms) curve BN254: n1={}  n2={}  m={}  i={}'.format(n1, n2, m, i) + '\n')
        f.write(algo_string + '\n')
        f.write(record1 + '\n')    
        f.write(record2 + '\n')
        f.write('\n')     
    open('Results/BN254.txt', 'r')  
    with open('Results/BN254.txt', 'a') as f:     
        f.write('*' * 70 + '\n')            
    return  
    
# ------------------------------------------------------ get parameters module ------------------------------------------------
def get_par(pairing_group, policy_str, attr_list):   
    msp_obj = MSP(pairing_group)
    policy = msp_obj.createPolicy(policy_str)
    mono_span_prog = msp_obj.convert_policy_to_msp(policy)
    nodes = msp_obj.prune(policy, attr_list)

    n1 = len(mono_span_prog) # number of rows
    n2 = msp_obj.len_longest_row # number of columns
    m = len(attr_list) # number of attributes
    i = len(nodes) # number of attributes in decryption

    return n1, n2, m, i

# -------------------------------------------------- Main functions module ---------------------------------------------------    
def create_policy_string_and_attribute_list(m, n):
    policy_string = '(1'
    attr_list = ['1']
    
    for i in range(2, m + 1):
        attr = str(i)
        attr_list.append(attr)
    
    for i in range(2, n + 1):
        attr = str(i)
        if i == m + 1:
            policy_string += ') or ('+ attr
        else: 
            policy_string += ' and ' + attr
        
    policy_string += ')'

    return policy_string, attr_list  
                  
def main():
    # instantiate a bilinear pairing map
    pairing_group = PairingGroup('BN254')
    msg = "hello world"
 
    #policy_sizes = [10]
    #attr_sizes = [10]
    
    #policy_sizes = [100]    
    #attr_sizes = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]
    
    policy_sizes = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]
    attr_sizes = [10]
    
    universe_size = 100
    _, attr_universe = create_policy_string_and_attribute_list(universe_size, 0)
    
    for policy_size in policy_sizes:
        for attr_size in attr_sizes:
            policy_str, attr_list = create_policy_string_and_attribute_list(attr_size, policy_size)
            #run_kp(pairing_group, len(attr_list) + 1, attr_list, policy_str, msg)
            run_sp(pairing_group, attr_universe, attr_list, policy_str, msg)
        
if __name__ == "__main__":
    debug = True
    main()                 
           
