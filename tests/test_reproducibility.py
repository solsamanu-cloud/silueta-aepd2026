"""Synthetic behavioural checks for the frozen published estimators."""
import sys
from pathlib import Path
import unittest
from unittest.mock import patch
import numpy as np
sys.path[:0]=[str(Path(__file__).resolve().parents[1]),str(Path(__file__).resolve().parents[1]/'live')]
from silueta.detector import scores, events, associate, calibrate
from silueta.spectral import averaged_spectrum
from dependencies import require_fields, missing_fields

class DetectorTests(unittest.TestCase):
    def test_second_high_second_low_strict_threshold_and_nan_reset(self):
        t=np.arange(10.)
        found,state=events(t,[1,2,2,1,1,2,np.nan,2,2,0],end=10,threshold=1)
        self.assertEqual(found,[dict(start_s=2.,end_s=4.,end_reason='two-low-scores'),
                                dict(start_s=8.,end_s=10.,end_reason='capture-end-censored')])
        self.assertFalse(state[6])
    def test_invalid_window_closes_active_event(self):
        e,_=events([0,1,2],[2,2,np.nan],threshold=1)
        self.assertEqual(e[0]['end_reason'],'invalid-data')
        self.assertEqual(e[0]['end_s'],2)
    def test_half_open_twenty_second_association_and_already_active(self):
        e=[dict(start_s=149.,end_s=155.),dict(start_s=170.,end_s=175.)]
        a=associate(e,[150.])[0]
        self.assertTrue(a['already_active']);self.assertIsNone(a['new_activation_delay_s'])
        self.assertEqual(associate([dict(start_s=150.,end_s=151.)],[150.])[0]['new_activation_delay_s'],0)
    def test_preparation_window_population_variance_and_gap(self):
        t=np.arange(118.,133.)
        tt,v=scores(t,t[:,None],start=120,end=132)
        self.assertTrue(np.isnan(v[:6]).all())
        self.assertAlmostEqual(v[6],4.) # variance of 120..126, ddof=0
        _,g=scores([120,121,122,126,127],np.arange(5)[:,None])
        self.assertTrue(np.isnan(g).all())
    def test_quantile_linear_and_nonincreasing_rejected(self):
        self.assertAlmostEqual(calibrate([0,1,np.nan]),.995)
        with self.assertRaises(ValueError):scores([1,1],[[0],[0]])

class SpectralTests(unittest.TestCase):
    def test_irregular_samples_linear_trend_and_power_weighted_mean(self):
        rng=np.random.default_rng(123)
        t=np.cumsum(rng.uniform(.8,1.8,240))
        a=np.sin(2*np.pi*.2*t);b=.1*np.sin(2*np.pi*.1*t)
        y=np.column_stack([a+3+.003*t,b-7-.002*t])
        f,p,v=averaged_spectrum(t,y)
        f0,p0,v0=averaged_spectrum(t,np.column_stack([a,b]))
        self.assertEqual(len(f),901);self.assertEqual((f[0],f[-1]),(.05,.35))
        self.assertAlmostEqual(f[np.argmax(p)],.2,places=3)
        np.testing.assert_allclose(p,p0,atol=1e-12)
        self.assertAlmostEqual(v,v0,places=12)
        # A normalize-per-component estimator would give the weak component equal weight.
        self.assertGreater(p[np.argmin(abs(f-.2))],20*p[np.argmin(abs(f-.1))])
    def test_no_peak_for_constant_series_and_too_short_explicit(self):
        f,p,v=averaged_spectrum(np.arange(100.),np.ones((100,2)))
        np.testing.assert_array_equal(p,np.zeros(901))
        with self.assertRaises(ValueError):averaged_spectrum([0,1],[[0],[1]])

class DependencyTests(unittest.TestCase):
    def test_raw_field_prefix_and_missing_fields(self):
        with patch('dependencies.available_tshark_fields',return_value={'wlan.test'}):
            self.assertEqual(missing_fields(['@wlan.test']),[])
            with self.assertRaisesRegex(RuntimeError,'4.6.7'):require_fields(['wlan.missing'])
    def test_skip_is_explicit_but_runtime_error_is_not_a_pass(self):
        from dependency_support import require_command, require_tshark
        with patch('dependency_support.shutil.which',return_value=None):
            with self.assertRaises(unittest.SkipTest):require_command('tcpdump')
        with patch('dependency_support.shutil.which',return_value='/example/tshark'),patch('dependencies.available_tshark_fields',return_value=set()):
            with self.assertRaisesRegex(unittest.SkipTest,'lacks fields'):
                require_tshark(['tshark','-e','wlan.missing'])

if __name__=='__main__':unittest.main()
