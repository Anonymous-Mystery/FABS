'''
| From: "FABS: Fast Attribute-Based Signatures"
| type:           SP-ABS scheme in Figure 2
| setting:        Type-III Pairing

:Authors:         
:Date:            02/2025
'''

from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from charm.toolbox.ABEnc import ABEnc
from msp import MSP

debug = False

class FABS_SPABS(ABEnc):
    def __init__(self, group_obj, verbose=False):
        ABEnc.__init__(self)
        self.name = "Our SP-ABS"
        self.group = group_obj
        self.util = MSP(self.group, verbose)

    def setup(self):
        # pick random elements from the two source groups
        g1, g2, g3 = self.group.random(G1), self.group.random(G2), self.group.random(G1)
                
       	# Pick master secret key
        alpha = self.group.random(ZR)    
        
        # Compute the master public key 
        e_g1g2_alpha = pair(g1, g2) ** alpha
      
        msk = {'alpha': alpha}
        mpk = {'g1': g1, 'g2': g2, 'g3': g3, 'e_g1g2_alpha': e_g1g2_alpha}
        
        return mpk, msk

    def keygen(self, mpk, msk, attr_list):
        # Pick randomness in secret key
        r = self.group.random(ZR)
        
        # Compute the secret key
        sk_1 = mpk['g1'] ** msk['alpha'] * mpk['g3'] ** r
            
        sk_2 = {}
        for attr in attr_list:
            attrHash = self.group.hash(attr, G1)
            sk_2[attr] = attrHash ** r
        
        sk_3 = mpk['g2'] ** r     
        
        sk = {'attr_list': attr_list, 'sk_1': sk_1, 'sk_2': sk_2, 'sk_3': sk_3}
                
        return sk

    def sign(self, mpk, sk, msg, policy_str, attr_list):
        # Convert the policy into MSP
        policy = self.util.createPolicy(policy_str)
        mono_span_prog = self.util.convert_policy_to_msp(policy)
        num_cols = self.util.len_longest_row

        # Compute the commitment of the policy matrix
        h_m = self.group.hash(str(mono_span_prog), ZR)
        
        # Create the public secret sharing vector a
        a = []
        for i in range(num_cols - 1):
            a.append(self.group.hash(str(i) + str(h_m), ZR))

        # pick randomness
        k, t = self.group.random(ZR), self.group.random(ZR)
	
        # Generate signature components A, B, C   
        nodes = self.util.prune(policy, attr_list)
        if not nodes:
            print ("Policy not satisfied.")
        
        A1 = sk['sk_1'] ** (a[0] * k * t)
        B1 = mpk['g3'] ** (a[0] * k)
        
        A2, B2 = 1, 1
        
        stripped_nodes = []
        for node in nodes:
            attr = node.getAttributeAndIndex()
            attr_stripped = self.util.strip_index(attr) 
            stripped_nodes.append(attr_stripped)
            A2 *= sk['sk_2'][attr_stripped]
            B2 *= self.group.hash(attr_stripped, G1)
        
               
        A = A1 * (A2 ** (k * t))        
        B = B1 * (B2 ** k)
        
        C = sk['sk_3'] ** t        
        
        # Generate the Schnorr signature components for zero-knowledge proof
        r_alpha = self.group.random(ZR)        
        r_i = {}
        
        
        Y = mpk['e_g1g2_alpha'] ** (a[0] * k * t)
        Z = mpk['e_g1g2_alpha'] ** (a[0] * r_alpha)
        
        W = 1       
        for attr, row in mono_span_prog.items():
            attr_stripped = self.util.strip_index(attr)
            attrHash = self.group.hash(attr_stripped, G1)
            len_row = len(row)
            Mivtop = sum(i[0] * i[1] for i in zip(row, a[:len_row]))
            
            r = self.group.random(ZR)
            r_i[attr] = r           
            W *= (mpk['g3'] ** Mivtop * attrHash) ** r
                   
        c = self.group.hash(str(A) + str(B) + str(C) + str(Y) + str(Z) + str(W) + str(msg), ZR)
        s_alpha = r_alpha - k * t * c
        s_i = {}
        
        for r_attr, r_value in r_i.items():
            if r_attr in stripped_nodes:
                s_i[r_attr] = r_value - k * c
            else:
                s_i[r_attr] = r_value
        
        signature = {'A': A, 'B': B, 'C': C, 'c': c, 's_alpha': s_alpha, 's_i': s_i}
            
        return signature
        
        
    def verify(self, mpk, signature, policy_str, msg):    
        # Convert the policy into MSP
        policy = self.util.createPolicy(policy_str)
        mono_span_prog = self.util.convert_policy_to_msp(policy)
        num_cols = self.util.len_longest_row    

        h_m = self.group.hash(str(mono_span_prog), ZR)

        a = []
        for i in range(num_cols - 1):
            a.append(self.group.hash(str(i) + str(h_m), ZR))
    
        # Recompute Y, Z, W, and verify Schnorr signature
        Y = pair(signature['A'], mpk['g2']) / (pair(signature['B'], signature['C']))
        Z = mpk['e_g1g2_alpha'] ** (a[0] * signature['s_alpha']) * Y ** signature['c']

        W = 1       
        for attr, row in mono_span_prog.items():
            attr_stripped = self.util.strip_index(attr)
            attrHash = self.group.hash(attr_stripped, G1)
            len_row = len(row)
            Mivtop = sum(i[0] * i[1] for i in zip(row, a[:len_row]))
                      
            W *= (mpk['g3'] ** Mivtop * attrHash) ** signature['s_i'][attr]      
        
        W *= signature['B'] ** signature['c']
                   
        if signature['c'] == self.group.hash(str(signature['A']) + str(signature['B']) + str(signature['C']) + str(Y) + str(Z) + str(W) + str(msg), ZR):
            return True
        else:
            return False

   

