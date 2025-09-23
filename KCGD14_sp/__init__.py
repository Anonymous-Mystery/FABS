'''
| From: "FABS: Fast Attribute-Based Signatures"
| type:           SP-ABS scheme in "Attribute-Based Signatures with User-Controlled Linkability"
| setting:        Type-III Pairing

:Authors:         
:Date:            08/2025
'''

from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from charm.toolbox.ABEnc import ABEnc
#from msp import MSP
from msp_full import MSP

debug = False

class KCGD14(ABEnc):
    def __init__(self, group_obj, verbose=False):
        ABEnc.__init__(self)
        self.name = "KCGD14 SP-ABS"
        self.group = group_obj
        self.util = MSP(self.group, verbose)

    def setup(self, attr_universe):
        # pick group elements from the two source groups
        g1, g2, h1 = self.group.random(G1), self.group.random(G2), self.group.random(G1)
        k1, k2, k3 = self.group.random(G1), self.group.random(G2), self.group.random(G1)
                
       	# Pick master secret key
        x, y = self.group.random(ZR), self.group.random(ZR)    
        
        # Compute the master public key 
        X, Y = g2 ** x, g2 ** y
        
        x_attr, y_attr = {}, {}
        X_attr, Y_attr = {}, {}
        
        for attr in attr_universe:
            x, y = self.group.random(ZR), self.group.random(ZR)
            x_attr[attr] = x
            y_attr[attr] = y
            X_attr[attr] = g2 ** x
            Y_attr[attr] = g2 ** y   
            
        msk = {'x_psdo': x, 'y_psdo': y, 'x_attr': x_attr, 'y_attr': y_attr}
        mpk = {'g1': g1, 'g2': g2, 'h1': h1, 'k1': k1, 'k2': k2, 'k3': k3, 'X_attr': X_attr, 'Y_attr': Y_attr, 'X_psdo': X, 'Y_psdo': Y}
        
        return mpk, msk

    def keygen(self, mpk, msk, attr_list):
        # User chooses a pair of public and secret key
        id_u = self.group.random(ZR)
        sk_u = self.group.random(ZR)
        pk_u = mpk['h1'] ** sk_u
    
        # AA generates attribute keys for users
        sigma, r_attr = {}, {}
        for attr in attr_list:
            r = self.group.random(ZR)      
            r_attr[attr] = r
            sigma[attr] = (mpk['g1'] * pk_u) ** (1 / (msk['x_attr'][attr] + r * msk['y_attr'][attr]  + self.group.hash(str(attr) + str(id), ZR)))
        
        sk = {'attr_list': attr_list, 'sk_u': sk_u, 'pk_u': pk_u, 'id_u': id_u, 'sigma': sigma, 'r_attr': r_attr}
                
        return sk

    def sign(self, mpk, sk, msg, policy_str, attr_list):
        # Convert the policy into MSP
        policy = self.util.createPolicy(policy_str)
        mono_span_prog = self.util.convert_policy_to_msp(policy)
        num_cols = self.util.len_longest_row
        
        # Compute the satisfied attribute subset
        nodes = self.util.prune(policy, attr_list)
        if not nodes:
            print ("Policy not satisfied.")
            
        stripped_nodes = []
        for node in nodes:
            attr = node.getAttributeAndIndex()
            attr_stripped = self.util.strip_index(attr) 
            stripped_nodes.append(attr_stripped) 
   
        # Commitments of vector         
        V, v_hat = {}, {}   
        beta_vi, beta_ti, ti = {}, {}, {}
        for attr in mono_span_prog.keys():
            beta_v, beta_t, t = self.group.random(ZR), self.group.random(ZR), self.group.random(ZR)
            beta_vi[attr] = beta_v
            beta_ti[attr] = beta_t
            ti[attr] = t
            
            V[attr] = mpk['g1'] ** beta_v * mpk['k3'] ** beta_t
            if attr in stripped_nodes:
                v_hat[attr] = mpk['g1'] * mpk['k3'] ** t
            else:
                v_hat[attr] = mpk['k3'] ** t
         
        # Proof of Statement
        A, lamb = {}, {}
        for j in range(num_cols - 1):
            a, la = 1, 1
            for attr in mono_span_prog.keys():
                M_ij = mono_span_prog[attr][j]
                a *= mpk['k3'] ** (ti[attr] * M_ij)
                la *= mpk['k3'] ** (beta_ti[attr] * M_ij)
                
            A[j] = a
            lamb[j] = la
        
        # Commitments of sigma, r, and signer identity id
        T, K, K_hat = {}, {}, {}
        X_prime, Y_prime, T_prime = {}, {}, {}
        X_ij_prime, Y_ij_prime, T_ij_prime, R_ij_prime = {}, {}, {}, {}
        rho_id, rho_sk, beta_rho_id, beta_sk, beta_rho_sk, beta_id = self.group.random(ZR), self.group.random(ZR), self.group.random(ZR), self.group.random(ZR), self.group.random(ZR), self.group.random(ZR)
        rho_vi, rho_ri, rho_i = {}, {}, {}
        beta_rho_vi, beta_rho_ri, beta_id_rho_vi, beta_ri, beta_rho_i, beta_ri_rho_vi = {}, {}, {}, {}, {}, {}
        
        R = pair(mpk['k1'], mpk['g2'])
        D_prime = pair(mpk['k1'], mpk['Y_psdo'])
        Z = sk['pk_u'] * mpk['k1'] ** rho_sk
        U = mpk['g2'] ** sk['id_u'] * mpk['k2'] ** rho_id      
        Z_hat = mpk['h1'] ** beta_sk * mpk['k1'] ** beta_rho_sk
        U_hat = mpk['g2'] ** beta_id * mpk['k2'] **  beta_rho_id        
        
        for attr in mono_span_prog.keys():
            rho_vi[attr], rho_ri[attr], beta_rho_vi[attr], beta_rho_ri[attr], beta_id_rho_vi[attr], beta_ri[attr], beta_rho_i[attr], beta_ri_rho_vi[attr] = self.group.random(ZR), self.group.random(ZR), self.group.random(ZR), self.group.random(ZR), self.group.random(ZR), self.group.random(ZR), self.group.random(ZR), self.group.random(ZR)
            
            if attr in stripped_nodes:
                T[attr] = sk['sigma'][attr] * mpk['k1'] ** rho_vi[attr]
                K[attr] = mpk['Y_attr'][attr] ** sk['r_attr'][attr] * mpk['k2'] ** rho_ri[attr]
            else:
                T[attr] = mpk['k1'] ** rho_vi[attr]       
                K[attr] = mpk['k2'] ** rho_ri[attr]
                     
            K_hat[attr] = mpk['Y_attr'][attr] ** beta_ri[attr] * mpk['k2'] ** beta_rho_ri[attr]
            rho_i[attr] = rho_ri[attr] + rho_id
            
            # Simplification
            X_prime[attr] = pair(mpk['k1'], mpk['X_attr'][attr]) 
            #* mpk['g2'] ** self.group.hash(str(attr) + str(id), ZR))
            Y_prime[attr] = pair(mpk['k1'], mpk['Y_attr'][attr])
            T_prime[attr] = pair(T[attr], mpk['k2'])
            
            # Knowledge of Exponents
            X_ij_prime[attr] = {}
            Y_ij_prime[attr] = {}
            T_ij_prime[attr] = {}
            R_ij_prime[attr] = {}
            for j in range(num_cols - 1):
                M_ij = mono_span_prog[attr][j]
                X_ij_prime[attr][j] = X_prime[attr] ** (M_ij * beta_rho_vi[attr])
                Y_ij_prime[attr][j] = Y_prime[attr] ** (M_ij * beta_ri_rho_vi[attr])
                T_ij_prime[attr][j] = T_prime[attr] ** (M_ij * beta_rho_i[attr])
                R_ij_prime[attr][j] = R ** (M_ij * beta_id_rho_vi[attr])
         
        B = {}
        for j in range(num_cols - 1):
            b = 1
            for attr in mono_span_prog.keys():       
                b *= X_ij_prime[attr][j] * Y_ij_prime[attr][j] * T_ij_prime[attr][j] * R_ij_prime[attr][j]
            B[j] = b
        
        # Schnorr signature
        c = self.group.hash(str(lamb) + str(V) + str(T) + str(K) + str(U) + str(K_hat) + str(U_hat) + str(Z), ZR)
        
        s_vi, s_ti, s_rho_vi, s_ri_rho_vi, s_rho_i, s_ri, s_rho_ri, s_id_rho_vi = {}, {}, {}, {}, {}, {}, {}, {}
        s_id = beta_id + c * sk['id_u']
        s_sk = beta_sk + c * sk['sk_u']
        s_rho_sk = beta_rho_sk + c * rho_sk
        s_rho_id = beta_rho_id + c * rho_id
        
        for attr in mono_span_prog.keys():
            if attr in stripped_nodes:
                s_vi[attr] = beta_vi[attr] + c
                s_ri_rho_vi[attr] = beta_ri_rho_vi[attr] + c * sk['r_attr'][attr] * rho_vi[attr]
                s_ri[attr] = beta_ri[attr] + c * sk['r_attr'][attr]
            else: 
                s_vi[attr] = beta_vi[attr]
                s_ri_rho_vi[attr] = beta_ri_rho_vi[attr] 
                s_ri[attr] = beta_ri[attr] 
                
            s_ti[attr] = beta_ti[attr] + c * ti[attr]
            s_rho_vi[attr] = beta_rho_vi[attr] + c * rho_vi[attr]
            s_rho_i[attr] = beta_rho_i[attr] + c * rho_i[attr]
            s_rho_ri[attr] = beta_rho_ri[attr] + c * rho_ri[attr]
            s_id_rho_vi[attr] = beta_id_rho_vi[attr] + c * sk['sk_u'] * rho_vi[attr]
        
        schnorr_sigma = {'c': c, 's_vi': s_vi, 's_ti': s_ti, 's_rho_vi': s_rho_vi, 's_ri_rho_vi': s_ri_rho_vi, 's_rho_i': s_rho_i, 's_ri': s_ri, 's_rho_ri': s_rho_ri, 's_id_rho_vi': s_id_rho_vi, 's_id': s_id, 's_sk': s_sk, 's_rho_sk': s_rho_sk, 's_rho_id': s_rho_id}
        signature = {'schnorr_sigma': schnorr_sigma, 'A': A, 'v_hat': v_hat, 'T': T, 'K': K, 'U': U, 'Z': Z, 'X_prime': X_prime, 'Y_prime': Y_prime, 'T_prime': T_prime, 'R': R, 'lamb': lamb, 'V': V, 'K_hat': K_hat, 'U_hat': U_hat, 'B': B, 'pk_u': sk['pk_u']}
            
        return signature
        
    def verify(self, mpk, signature, policy_str, msg):    
        # Convert the policy into MSP
        policy = self.util.createPolicy(policy_str)
        mono_span_prog = self.util.convert_policy_to_msp(policy)
        num_cols = self.util.len_longest_row    
    
        V, K_hat = {}, {}
        lamb, B, E = {}, {}, {}
        for j in range(num_cols - 1):
            e = 1
            for attr in mono_span_prog.keys():       
                e *= pair(signature['T'][attr], (mpk['X_attr'][attr] * signature['K'][attr] * signature['U']) ** mono_span_prog[attr][j])
            E[j] = e / (pair(mpk['g1'], mpk['g2']) * pair(signature['pk_u'], mpk['g2']))

        U_hat = mpk['g2'] ** signature['schnorr_sigma']['s_id'] * mpk['k2'] ** signature['schnorr_sigma']['s_rho_id'] * signature['U'] ** (- signature['schnorr_sigma']['c'])
        Z_hat = mpk['h1'] ** signature['schnorr_sigma']['s_sk'] * mpk['k1'] ** signature['schnorr_sigma']['s_rho_sk'] * signature['Z'] ** (- signature['schnorr_sigma']['c'])
        
        for attr in mono_span_prog.keys():
            V[attr] = mpk['g1'] ** signature['schnorr_sigma']['s_vi'][attr] * mpk['k3'] ** signature['schnorr_sigma']['s_ti'][attr] * signature['v_hat'][attr] ** (- signature['schnorr_sigma']['c'])
            K_hat[attr] = mpk['Y_attr'][attr] ** signature['schnorr_sigma']['s_ri'][attr] * mpk['k2'] ** signature['schnorr_sigma']['s_rho_ri'][attr] * signature['K'][attr] ** (- signature['schnorr_sigma']['c'])
        
        for j in range(num_cols - 1):
            la, b = signature['A'][j] ** (- signature['schnorr_sigma']['c']), E[j] ** (- signature['schnorr_sigma']['c']) 
            for attr in mono_span_prog.keys():  
                la *=  mpk['k3'] ** (mono_span_prog[attr][j] * signature['schnorr_sigma']['s_ti'][attr])
                b *= signature['X_prime'][attr] ** (mono_span_prog[attr][j] * signature['schnorr_sigma']['s_rho_vi'][attr]) * signature['Y_prime'][attr] ** (mono_span_prog[attr][j] * signature['schnorr_sigma']['s_ri_rho_vi'][attr]) * signature['R'] ** (mono_span_prog[attr][j] * signature['schnorr_sigma']['s_id_rho_vi'][attr]) * signature['T_prime'][attr] ** (mono_span_prog[attr][j] * signature['schnorr_sigma']['s_rho_i'][attr]) 
            lamb[j] = la
            B[j] = b
    
        c = self.group.hash(str(lamb) + str(V) + str(signature['T']) + str(signature['K']) + str(signature['U']) + str(K_hat) + str(U_hat) + str(signature['Z']), ZR)
        
        if signature['schnorr_sigma']['c'] == c:
            return True
        else:
            return False

   

