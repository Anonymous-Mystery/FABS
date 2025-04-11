'''
| From: "Efficient attribute-based signature and signcryption realizing expressive access structures"
| type:           The large universe KP-ABS scheme in RD16
| setting:        Type-III Pairing

:Authors:         
:Date:            02/2025
'''

from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from charm.toolbox.ABEnc import ABEnc
from msp import MSP
import numpy as np

debug = False

class RD16(ABEnc):
    def __init__(self, group_obj, verbose=False):
        ABEnc.__init__(self)
        self.name = "RD16 KP-ABS"
        self.group = group_obj
        self.util = MSP(self.group, verbose)

    def setup(self, n):
        # pick two generators from the two source groups
        g1, g2 = self.group.random(G1), self.group.random(G2)
                
       	# Pick master secret key
        alpha = self.group.random(ZR)    
        
        # Pick generators for the maximum bound n and hash output bits l
        V = []
        for i in range(n + 1):
            V.append(self.group.random(G1))

        u = []    
        for i in range(80):
            u.append(self.group.random(G1))
        
        # Compute the master public key 
        Y = pair(g1, g2) ** alpha
      
        msk = {'alpha': alpha}
        mpk = {'g1': g1, 'g2': g2, 'Y': Y, 'V': V, 'u': u, 'n': n}
        
        return mpk, msk

    def keygen(self, mpk, msk, policy_str):
        # Convert the policy into MSP
        policy = self.util.createPolicy(policy_str)
        mono_span_prog = self.util.convert_policy_to_msp(policy)
        num_cols = self.util.len_longest_row
        
        # pick random shares
        v = [msk['alpha']]
        for i in range(num_cols - 1):
            rand = self.group.random(ZR)
            v.append(rand)        

        # Compute the secret key        
        D, D_prime, D_prime_prime = {}, {}, {}
        for attr, row in mono_span_prog.items():
            attr_stripped = self.util.strip_index(attr)
            attr_hash = self.group.hash(attr_stripped, ZR)           
            r = self.group.random(ZR)
            len_row = len(row)
            Mivtop = sum(i[0] * i[1] for i in zip(row, v[:len_row]))
            D[attr] = mpk['g1'] ** Mivtop * mpk['V'][0] ** r
            D_prime[attr] = mpk['g2'] ** r

            D_prime_prime[attr] = {}
            for x in range(2, mpk['n'] + 1):
                D_prime_prime[attr][x] = (mpk['V'][1] ** (-attr_hash ** (x - 1)) * mpk['V'][x]) ** r

        sk = {'policy_str': policy_str, 'D': D, 'D_prime': D_prime, 'D_prime_prime': D_prime_prime}
                
        return sk

    def sign(self, mpk, sk, msg, policy_str, attr_list):
        # Convert the policy into MSP
        policy = self.util.createPolicy(policy_str)
        mono_span_prog = self.util.convert_policy_to_msp(policy)
        num_cols = self.util.len_longest_row
       	 
        nodes = self.util.prune(policy, attr_list)
        if not nodes:
            print ("Policy not satisfied.")

        # Construct a polynomial with roots at each attribute in the attribute list    
        W = []
        for node in nodes:
            attr = node.getAttributeAndIndex()
            attr_stripped = self.util.strip_index(attr) 
            attr_hash = self.group.hash(attr_stripped, ZR)
            W.append(attr_hash)
               
        poly_coeffs = np.poly(W)        
        y = poly_coeffs[::-1]
        
        while len(y) < mpk['n']:
            y.append(0)
        
        #if mpk['V'][1] ** y[0] == (mpk['V'][1] ** -W[0]) ** (y[1]) * (mpk['V'][1] ** (-W[0] ** 2)) ** (y[2]):
        #    print('This is right')
        #else:
        #    print('This is wrong')
        

        # Construct the signature 
        theta, epsilon = self.group.random(ZR), self.group.random(ZR)
        
        sigma_1 = mpk['g2'] ** theta
        sigma_2 = mpk['g2'] ** epsilon           
        sigma_3_p1 = 1
        
        for attr in attr_list:
            sigma_2 *= sk['D_prime'][attr]
                       
            sigma_3_p1 *= sk['D'][attr]
            for x in range(2, mpk['n'] + 1):
                sigma_3_p1 *= sk['D_prime_prime'][attr][x] ** y[x - 1] 
            
        sigma_3_p2 = mpk['V'][0]
        for k in range(1, mpk['n'] + 1):
            sigma_3_p2 *= mpk['V'][k] ** y[k - 1]             
        sigma_3_p2 **= epsilon 
 
        signed_msg = self.group.hash(str(msg) + str(sigma_2) + str(attr_list), ZR)
        signed_msg = str(signed_msg)    
                    
        sigma_3_p3 = mpk['u'][0]
        for j in range(len(signed_msg)):
            sigma_3_p3 *= mpk['u'][j] ** int(signed_msg[j])
        sigma_3_p3 **= theta
                   
        sigma_3 = sigma_3_p1 * sigma_3_p2 * sigma_3_p3
        
        signature = {'sigma_1': sigma_1, 'sigma_2': sigma_2, 'sigma_3': sigma_3}
            
        return signature
                
    def verify(self, mpk, signature, attr_list, msg):       
        # Recompute the signed message
        signed_msg = self.group.hash(str(msg) + str(signature['sigma_2']) + str(attr_list), ZR)
        signed_msg = str(signed_msg)
        print(len(signed_msg))
        
        # Recompute all the y_values from the polynomial
        W = []
        for attr in attr_list:
            attr_hash = self.group.hash(attr, ZR)
            W.append(attr_hash)
            
        poly_coeffs = np.poly(W)        
        y = poly_coeffs[::-1]
        
        while len(y) < mpk['n']:
            y.append(0)        
        
        e1 = mpk['V'][0]
        for k in range(1, mpk['n'] + 1):
            e1 *= mpk['V'][k] ** y[k - 1]

        e2 = mpk['u'][0]
        for j in range(len(signed_msg)):
            print(len(signed_msg))
            e2 *= mpk['u'][j] ** int(signed_msg[j])
        
        if pair(signature['sigma_3'], mpk['g2']) == mpk['Y'] * pair(e1, signature['sigma_2']) * pair(e2, signature['sigma_1']):     
            return True
        else:
            return False

   

