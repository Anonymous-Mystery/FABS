'''
| From: "FABS: Fast Attribute-Based Signatures"
| type:           KP-ABS scheme in Figure 1
| setting:        Type-III Pairing

:Authors:         
:Date:            02/2025
'''

from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from charm.toolbox.ABEnc import ABEnc
from msp import MSP

debug = False

class FABS_KPABS(ABEnc):
    def __init__(self, group_obj, verbose=False):
        ABEnc.__init__(self)
        self.name = "Our KP-ABS"
        self.group = group_obj
        self.util = MSP(self.group, verbose)

    def setup(self, n):
        # pick random elements from the two source groups
        g1, g2 = self.group.random(G1), self.group.random(G2)
                
       	# Pick master secret key
        alpha = self.group.random(ZR)    
        
        # Compute the master public key 
        e_g1g2_alpha = pair(g1, g2) ** alpha
      
        msk = {'alpha': alpha}
        mpk = {'g1': g1, 'g2': g2, 'e_g1g2_alpha': e_g1g2_alpha}
        
        return mpk, msk

    def keygen(self, mpk, msk, policy_str):
        # Convert the policy into MSP
        policy = self.util.createPolicy(policy_str)
        mono_span_prog = self.util.convert_policy_to_msp(policy)
        num_cols = self.util.len_longest_row

        # Pick randomness in secret key
        r = self.group.random(ZR)
        
        # pick random shares
        v = [msk['alpha'] + r]
        for i in range(num_cols - 1):
            rand = self.group.random(ZR)
            v.append(rand)        

        # Compute the secret key        
        sk_1 = mpk['g2'] ** r
            
        sk_2 = {}
        for attr, row in mono_span_prog.items():
            attr_stripped = self.util.strip_index(attr)
            attrHash = self.group.hash(attr_stripped, G1)
            len_row = len(row)
            Mivtop = sum(i[0] * i[1] for i in zip(row, v[:len_row]))
            sk_2[attr] = mpk['g1'] ** Mivtop * attrHash ** r
                          
        sk = {'policy_str': policy_str, 'sk_1': sk_1, 'sk_2': sk_2}
                
        return sk

    def sign(self, mpk, sk, msg, policy_str, attr_list):
        # Convert the policy into MSP
        policy = self.util.createPolicy(policy_str)
        mono_span_prog = self.util.convert_policy_to_msp(policy)
        num_cols = self.util.len_longest_row
       
        # pick randomness
        k, t = self.group.random(ZR), self.group.random(ZR)
	
        # Generate signature components A, B, C   
        nodes = self.util.prune(policy, attr_list)
        if not nodes:
            print ("Policy not satisfied.")
        
        A = 1       
        B1 = mpk['g1'] ** k    
        B2 = 1  
          
        # Generate the Schnorr signature components for zero-knowledge proof
        r_alpha, r_k = self.group.random(ZR), self.group.random(ZR)         
        r_i = {}        
        W = mpk['g1'] ** r_k  
        
        stripped_nodes = []
        for node in nodes:
            attr = node.getAttributeAndIndex()
            attr_stripped = self.util.strip_index(attr) 
            stripped_nodes.append(attr_stripped)
            A *= sk['sk_2'][attr_stripped]
            attr_hash = self.group.hash(attr_stripped, G1)
            B2 *= attr_hash
            
            r = self.group.random(ZR)
            r_i[attr] = r              
            W *= attr_hash ** r
            
        A = A ** (k * t)   
        B = B1 * B2 ** k    
                 
        C = sk['sk_1'] ** t        
                      
        Y = mpk['e_g1g2_alpha'] ** (k * t)
        Z = mpk['e_g1g2_alpha'] ** r_alpha
                               
        c = self.group.hash(str(A) + str(B) + str(C) + str(Y) + str(Z) + str(W) + str(msg), ZR)
        s_alpha = r_alpha - k * t * c
        s_i = {}
        
        for r_attr, r_value in r_i.items():
            s_i[r_attr] = r_value - k * c
	
        s_k = r_k - k * c
        
        signature = {'A': A, 'B': B, 'C': C, 'c': c, 's_alpha': s_alpha, 's_k': s_k, 's_i': s_i}
            
        return signature
                
    def verify(self, mpk, signature, attr_list, msg):       
        # Recompute Y, Z, W, and verify Schnorr signature
        Y = pair(signature['A'], mpk['g2']) / (pair(signature['B'], signature['C']))
        Z = mpk['e_g1g2_alpha'] ** (signature['s_alpha']) * Y ** signature['c']
        
        W = mpk['g1'] ** signature['s_k']      
        for attr in attr_list:
            attrHash = self.group.hash(attr, G1)
            W *= attrHash ** signature['s_i'][attr] 
            
        W *= signature['B'] ** signature['c']
          
        if signature['c'] == self.group.hash(str(signature['A']) + str(signature['B']) + str(signature['C']) + str(Y) + str(Z) + str(W) + str(msg), ZR):
            return True
        else:
            return False

   

