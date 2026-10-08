import sys,unittest
from pathlib import Path
import numpy as np
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'live'))
from engine import RollingVariance
class PhiTests(unittest.TestCase):
 def result(self,phases):
  e=RollingVariance()
  for t,p in enumerate(phases):r=e.push(t,np.array([.2]),(1,),np.array([p]))
  return r
 def test_wrap(self):
  r=self.result([.01,2*np.pi-.01]*4)
  self.assertLess(r['variance_phi'],.0001)
  self.assertAlmostEqual(r['variance'],0)
 def test_constant(self):
  self.assertAlmostEqual(self.result([1.2]*8)['variance_phi'],0)
 def test_spread(self):
  self.assertGreater(self.result([0,np.pi]*4)['variance_phi'],.8)
 def test_gap(self):
  e=RollingVariance();e.push(0,np.array([0]),(1,),np.array([0]))
  r=e.push(10,np.array([0]),(1,),np.array([1]));self.assertAlmostEqual(r['variance_phi'],0);self.assertTrue(r['single_sample']);self.assertFalse(r['reliable'])
 def test_legacy(self):
  e=RollingVariance()
  for t in range(8):r=e.push(t,np.array([0]),(1,))
  self.assertIsNone(r['variance_phi'])
if __name__=='__main__':unittest.main()
