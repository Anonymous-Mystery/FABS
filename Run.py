'''
:Date:            04/2025
'''
import re, random
from charm.toolbox.pairinggroup import PairingGroup, G1, G2, GT, ZR
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.policytree import PolicyParser

from FABS_sp import FABS_SPABS
from FABS_kp import FABS_KPABS
from RD16_kp import RD16
from KCGD14_sp import KCGD14

def run_kp(ABS, n, attr_list, attr_policy, msg):
    (mpk, msk) = ABS.setup(n)
    sk = ABS.keygen(mpk, msk, attr_policy)
    signature = ABS.sign(mpk, sk, msg, attr_policy, attr_list)
    result = ABS.verify(mpk, signature, attr_list, msg)
    if result:
        print("The ABS verification for {} is passed!".format(ABS.name))
    else:
        print("The ABS verification for {} is wrong!".format(ABS.name))
        
def run_sp(ABS, attr_universe, attr_list, attr_policy, msg):
    (mpk, msk) = ABS.setup(attr_universe)
    sk = ABS.keygen(mpk, msk, attr_list)
    signature = ABS.sign(mpk, sk, msg, attr_policy, attr_list)
    result = ABS.verify(mpk, signature, attr_policy, msg)
    if result:
        print("The ABS verification for {} is passed!".format(ABS.name))
    else:
        print("The ABS verification for {} is wrong!".format(ABS.name))
                   
def main():
    # instantiate a bilinear pairing map
    pairing_group = PairingGroup('BN254')
                
    attr_universe = ['1', '2', '3', '4']
    attr_list = ['1', '2']
    attr_policy = '((1 and 2) or (3 and 4))'    
    msg = 'hello world'
    n = 3
       
    fabs_spabs = FABS_SPABS(pairing_group)
    fabs_kpabs = FABS_KPABS(pairing_group)
    rd16_kpabs = RD16(pairing_group)
    kcgd14_spabs = KCGD14(pairing_group)
    run_kp(fabs_kpabs, n, attr_list, attr_policy, msg)
    run_kp(rd16_kpabs, n, attr_list, attr_policy, msg)
    run_sp(fabs_spabs, attr_universe, attr_list, attr_policy, msg)   
    run_sp(kcgd14_spabs, attr_universe, attr_list, attr_policy, msg)
             
if __name__ == "__main__":
    debug = True
    main()
