"""
@author Yannick Chevalier
@date 2026
"""

class Contexts:
    contexts=set([]) # type set
    def __init__(self,ctxts=[]):
        self.contexts=set(ctxts)
    def add(self,ctxt):
        self.contexts.add(ctxt)
    def printContexts(self): # pour debug
        print(self.contexts)
    def compare(self,aContext):
        lowerOrEq=(self.contexts <= aContext.contexts)
        greaterOrEq=(self.contexts >= aContext.contexts)
        if lowerOrEq and greaterOrEq:
            return 0 # equal
        elif lowerOrEq:
            return -1
        elif greaterOrEq:
            return 1
        else:
            return None


class SecurityLevel:
    hierarchy=None
    contexts=None
    level=None
    def __init__(self,classification=hierarchy,ctxts=[],level=None):
        self.contexts=Contexts(ctxts)
        self.level=level
        self.hierarchy=classification
    def compare(self,aSecurityLevel):
        if not ( self.hierarchy == aSecurityLevel.hierarchy):
            return None
        ctxtcmp=self.contexts.compare(aSecurityLevel.contexts)
        levelcmp=self.hierarchy.compare(self.level,aSecurityLevel.level)
        # if either is incomparable, the result is incomparable
        if ctxtcmp is None or levelcmp is None:
            return None
        # if they are both non-zero but of a different sign, the result is None
        if ctxtcmp * levelcmp < 0:
            return None
        # if they agree (or equal)...
        return ctxtcmp+levelcmp
    def printLevel(self):
        print(f'hierarchy={self.hierarchy}, contexts={self.contexts.printContexts()}, level={self.level}')

class Classification:
    # classification is a dictionary that stores, for each security
    # level, all the levels strictly below it
    classification=None
    def __init__(self):
        self.classification=dict([])
    def addClassificationLevel(self,level,above=[]):
        # adds a level above those listed
        s= set(above)
        for lvl in above:
            s_level=self.classification.get(lvl)
            if s_level is not None:
                s=s.union(s_level)
        if level in s:
            raise Exception (f'Error, level {level} is already defined and below one of the levels it should be above')
        self.classification[level]=s
    def securityLevel(self,ctxts=[],level=None):
        if level not in self.classification:
            raise Exception(f'Level {level} is not known in this classification')
        return SecurityLevel(classification=self,ctxts=ctxts,level=level)
    def compare(self,level1,level2):
        if level1 == level2:
            return 0
        s1 = self.classification.get(level1)
        s2 = self.classification.get(level2)
        if s1 is None:
            raise Exception (f'Error, level {level1} is not defined in this classification')
        if s2 is None:
            raise Exception (f'Error, level {level2} is not defined in this classification')
        if level1 == level2:
            return 0
        if level1 in s2:
            return -1
        if level2 in s1:
            return 1
        return None


class Sujet:
    def __init__(self, id, groupe, niveau, niveau_max=None):
        self.id = id
        self.groupe = groupe
        self.niveau = niveau
        if niveau_max == None:
            self.niveau_max = niveau
        else:
            self.niveau_max = niveau_max
        # listes pour la partie 4
        self.lecture_en_cours = []
        self.ecriture_en_cours = []

class Objet:
    def __init__(self, id, groupe, niveau, proprio, trusted=False):
        self.id = id
        self.groupe = groupe
        self.niveau = niveau
        self.proprio = proprio
        self.trusted = trusted

class Controleur(Classification):
    def __init__(self):
        super().__init__()
        self.sujets = []
        self.objets = []
        self.matrice_dac = {} 

    def verif_dac(self, s, o, droit):
        # le proprio a tous les droits
        if o.proprio == s:
            return True
        droits_liste = self.matrice_dac.get((s.id, o.id), [])
        if droit in droits_liste:
            return True
        return False

    def read(self, s, o):
        if self.verif_dac(s,o, 'r') == False:
            return False
        cmp = s.niveau_max.compare(o.niveau)
        if cmp != None and cmp >= 0:
            return True
        return False

    def write(self, s, o):
        if self.verif_dac(s,o,'w') == False:
            return False
        cmp = s.niveau.compare(o.niveau)
        if cmp != None and cmp <= 0:
            return True
        return False

    def execute(self, s,prog,niveau_voulu):
        if self.verif_dac(s, prog, 'x') == False:
            return None
        
        if prog.trusted == False:
            c = niveau_voulu.compare(s.niveau)
            if c == None or c > 0:
                return None

        nom_fils = s.id +"_fils_" + prog.id
        nouveau = Sujet(nom_fils, s.groupe, niveau_voulu, niveau_voulu)
        self.sujets.append(nouveau)
        return nouveau

    def kill(self, s, cible):
        if s == cible or self.verif_dac(s, cible, 'x'):
            if cible in self.sujets:
                self.sujets.remove(cible)
                return True
        return False

    def readOpen(self, s, o):
        if self.read(s, o):
            if o not in s.lecture_en_cours:
                s.lecture_en_cours.append(o)
            return True
        return False

    def writeOpen(self, s, o):
        if self.write(s, o):
            if o not in s.ecriture_en_cours:
                s.ecriture_en_cours.append(o)
            return True
        return False

    def close(self, s, o):
        if o in s.lecture_en_cours:
            s.lecture_en_cours.remove(o)
        if o in s.ecriture_en_cours:
            s.ecriture_en_cours.remove(o)

    def touch(self, s, id_objet, trusted=False):
        nouveau_obj = Objet(id_objet, s.groupe, s.niveau, s, trusted)
        self.objets.append(nouveau_obj)
        return nouveau_obj

    def rm(self, s, o):
        if o.proprio == s:
            if o in self.objets:
                self.objets.remove(o)
                return True
        return False

    def chmod(self, s, o, autre_sujet, nouveaux_droits):
        if o.proprio== s:
            self.matrice_dac[(autre_sujet.id, o.id)] = nouveaux_droits
            return True
        return False

    def chown(self, s, o, nouveau_proprio):
        if o.proprio==s:
            o.proprio= nouveau_proprio
            return True
        return False

    def changerNiveau(self, s, nouveau_niv):
        c_max = nouveau_niv.compare(s.niveau_max)
        if c_max ==None or c_max > 0:
            return False
            
        for obj in s.lecture_en_cours:
            c = nouveau_niv.compare(obj.niveau)
            if c ==None or c < 0: # on descend trop bas pour lire l'objet
                return False
                
        for obj in s.ecriture_en_cours:
            c = nouveau_niv.compare(obj.niveau)
            if c == None or c > 0: # on monte trop haut pour ecrire l'objet
                return False
        
        s.niveau = nouveau_niv
        return True


if __name__ == '__main__':
    systeme = Controleur()
    systeme.addClassificationLevel('public')
    systeme.addClassificationLevel('secret', above=['public'])
    systeme.addClassificationLevel('topsecret', above=['secret'])

    p = systeme.securityLevel([], 'public')
    s = systeme.securityLevel(['info'], 'secret')
    ts = systeme.securityLevel(['info'], 'topsecret')

    alice = Sujet('alice', 'equipe1', s, niveau_max=ts)
    bob = Sujet('bob', 'equipe2', p)
    systeme.sujets.append(alice)
    systeme.sujets.append(bob)

    doc_secret = Objet('doc_secret', 'equipe1', s, alice)
    doc_public = Objet('doc_public', 'equipe2', p, bob)
    systeme.objets.append(doc_secret)
    systeme.objets.append(doc_public)

    # test droit de base
    print("Alice lit secret:", systeme.read(alice, doc_secret))
    print("Bob lit secret :", systeme.read(bob, doc_secret))
    
    # test changement niveau
    print("Alice passe en TS:", systeme.changerNiveau(alice, ts))
    
    # test creation
    nouveau = systeme.touch(alice, 'note_ts')
    print("Niveau note_ts:", nouveau.niveau.level)
    
    # test blocage changement niveau
    systeme.writeOpen(alice, nouveau)
    print("Alice descend en public avec fichier TS ouvert ", systeme.changerNiveau(alice, p))