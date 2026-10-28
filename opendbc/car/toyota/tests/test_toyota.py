import itertools
import gzip
import hashlib
import json
import unittest
from pathlib import Path

import pytest
from opendbc.car.tests.dbc_adapter import sienna_dbc_adapter  # noqa: F401

from opendbc.can import CANParser
from opendbc.car import Bus, gen_empty_fingerprint, structs
from opendbc.car.structs import CarParams
from opendbc.car.fw_versions import build_fw_dict
from opendbc.car.toyota.fingerprints import FW_VERSIONS
from opendbc.car.toyota.values import CAR, DBC, ToyotaFlags, FW_QUERY_CONFIG, PLATFORM_CODE_ECUS, \
                                                  FUZZY_EXCLUDED_PLATFORMS, get_platform_codes
from opendbc.car.toyota.interface import CarInterface
from opendbc.testing import fuzzy_test

Ecu = CarParams.Ecu
pytestmark = pytest.mark.usefixtures('sienna_dbc_adapter')


def check_fw_version(fw_version: bytes) -> bool:
  # TODO: just use the FW patterns, need to support all chunks
  return b'?' not in fw_version and b'!' not in fw_version


def cars_with(flags):
  return {c for c in CAR if c.config.flags & flags}


def legacy_can_trace(platform, varied=False):
  CP = CarInterface.get_params(platform, gen_empty_fingerprint(), [], alpha_long=False, is_release=False, docs=False)
  interface = CarInterface(CP, structs.CarParamsSP())
  interface.update([])
  control = structs.CarControl(enabled=True, latActive=True)
  control.actuators.torque = 0.5
  trace = []
  for frame in range(240 if varied else 36):
    control.latActive = not varied or frame < 200
    control.actuators.steeringAngleDeg = 10 + frame / 10
    state = interface.CS.out
    state.vEgo = state.vEgoRaw = 10
    state.steeringAngleDeg = 5
    state.steeringTorque = (0, 80, 100, 150, 212, -212, 500, 0)[frame // 30] if varied else 0
    state.steeringPressed = abs(state.steeringTorque) > 100
    state.steeringRateDeg = 600 if varied else 0
    _, messages = interface.apply(control.as_reader(), structs.CarControlSP(), frame * 10_000_000)
    trace.extend(f"{frame}:{address}:{data.hex()}:{bus}\n" for address, data, bus in messages)
  return "".join(trace).encode()


def lta_angle_command_after(initial_angle, desired_angle, speed, frames, activate=True, return_first_byte=False):
  CP = CarInterface.get_params(CAR.TOYOTA_SIENNA_PATCHED_LTA, gen_empty_fingerprint(), [],
                               alpha_long=False, is_release=False, docs=False)
  interface = CarInterface(CP, structs.CarParamsSP())
  interface.update([])
  control = structs.CarControl(enabled=True, latActive=False)
  control.actuators.steeringAngleDeg = initial_angle
  state = interface.CS.out
  state.vEgo = state.vEgoRaw = speed
  state.steeringAngleDeg = initial_angle
  state.steeringTorque = 0
  state.steeringPressed = False
  parser = CANParser(DBC[CP.carFingerprint][Bus.pt], [("STEERING_LTA_2", 50)], 0)
  first_byte = 0
  for frame in range(frames):
    if frame == 1 and activate:
      control.latActive = True
      control.actuators.steeringAngleDeg = desired_angle
    _, messages = interface.apply(control.as_reader(), structs.CarControlSP(), frame * 10_000_000)
    for address, data, _ in messages:
      if address == 0x131:
        first_byte = data[0]
    parser.update([(frame * 10_000_000, messages)])
  angle = parser.vl["STEERING_LTA_2"]["STEER_ANGLE_CMD"]
  return (angle, first_byte) if return_first_byte else angle


def lta_angle_command_with_feedback(desired_angle, feedback_angle, frames, override_frame=None):
  CP = CarInterface.get_params(CAR.TOYOTA_SIENNA_PATCHED_LTA, gen_empty_fingerprint(), [],
                               alpha_long=False, is_release=False, docs=False)
  interface = CarInterface(CP, structs.CarParamsSP())
  interface.update([])
  control = structs.CarControl(enabled=True, latActive=False)
  control.actuators.steeringAngleDeg = desired_angle
  state = interface.CS.out
  state.vEgo = state.vEgoRaw = 3.86
  state.steeringAngleDeg = feedback_angle
  state.steeringTorque = 0
  state.steeringPressed = False
  parser = CANParser(DBC[CP.carFingerprint][Bus.pt], [("STEERING_LTA_2", 50)], 0)
  for frame in range(frames):
    if frame == 1:
      control.latActive = True
    if frame == override_frame:
      state.steeringPressed = True
    _, messages = interface.apply(control.as_reader(), structs.CarControlSP(), frame * 10_000_000)
    parser.update([(frame * 10_000_000, messages)])
  return parser.vl["STEERING_LTA_2"]["STEER_ANGLE_CMD"]


class TestToyotaSiennaLtaAngleCommand(unittest.TestCase):
  def test_outer_loop_corrects_small_angle_error(self):
    self.assertAlmostEqual(lta_angle_command_with_feedback(5, 0, 5), 5.505, delta=0.0573)

  def test_outer_loop_large_error_does_not_add_correction(self):
    self.assertAlmostEqual(lta_angle_command_with_feedback(100, 0, 5), 20, delta=0.0573)

  def test_outer_loop_resets_integral_on_driver_override(self):
    self.assertAlmostEqual(lta_angle_command_with_feedback(5, 0, 6, override_frame=3), 0, delta=0.0573)

  def test_vm_large_angle_command_tracks_up_at_low_speed(self):
    self.assertAlmostEqual(lta_angle_command_after(27.27, 91.42, 3.86, 101), 91.42, delta=0.0573)

  def test_vm_large_angle_command_tracks_down_at_low_speed(self):
    self.assertAlmostEqual(lta_angle_command_after(91.42, 0, 3.86, 101), 0, delta=0.0573)

  def test_vm_lateral_accel_limits_at_high_speed(self):
    self.assertAlmostEqual(lta_angle_command_after(27.27, 91.42, 25, 101), 31.74, delta=0.06)
    self.assertAlmostEqual(lta_angle_command_after(27.27, 91.42, 15, 101), 63.6, delta=0.06)

  def test_high_mode_angle_cap_is_180_degrees(self):
    self.assertAlmostEqual(lta_angle_command_after(0, 200, 3.86, 101), 180.0366, delta=0.0573)

  def test_high_output_mode_bit_is_only_set_when_active(self):
    _, active_first_byte = lta_angle_command_after(0, 45, 3.86, 3, return_first_byte=True)
    _, inactive_first_byte = lta_angle_command_after(0, 45, 3.86, 1, activate=False, return_first_byte=True)
    self.assertEqual(active_first_byte & 0x02, 0x02)
    self.assertEqual(inactive_first_byte & 0x02, 0)


class TestToyotaLtaDriverOverride(unittest.TestCase):
  def setUp(self):
    CP = CarInterface.get_params(CAR.TOYOTA_SIENNA_PATCHED_LTA, gen_empty_fingerprint(), [],
                                 alpha_long=False, is_release=False, docs=False)
    self.interface = CarInterface(CP, structs.CarParamsSP())
    self.interface.update([])
    self.control = structs.CarControl(enabled=True, latActive=True)
    self.control.actuators.steeringAngleDeg = 115.25
    self.parser = CANParser(DBC[CP.carFingerprint][Bus.pt],
                            [("STEERING_LTA", 50), ("STEERING_LTA_2", 50), ("STEERING_LKA", 100)], 0)
    self.frame = 0

  def step(self, **state):
    for name, value in state.items():
      setattr(self.interface.CS.out, name, value)
    _, messages = self.interface.apply(self.control.as_reader(), structs.CarControlSP(), self.frame * 10_000_000)
    self.parser.update([(self.frame * 10_000_000, messages)])
    self.frame += 1
    return messages

  def assert_lta(self, active, angle=None):
    # EPS arbitration must see only LTA2; simultaneous legacy + LTA2 rising selects no mode.
    self.assertEqual(self.parser.vl["STEERING_LTA"]["STEER_REQUEST"], False)
    self.assertEqual(self.parser.vl["STEERING_LTA"]["STEER_REQUEST_2"], False)
    self.assertEqual(self.parser.vl["STEERING_LTA_2"]["STEER_REQUEST"], active)
    self.assertEqual(self.parser.vl["STEERING_LTA_2"]["STEER_REQUEST_2"], active)
    self.assertEqual(self.parser.vl["STEERING_LTA"]["TORQUE_WIND_DOWN"], 100 if active else 0)
    self.assertEqual(self.parser.vl["STEERING_LTA"]["STEER_ANGLE_CMD"], 0)
    self.assertEqual(self.parser.vl["STEERING_LKA"]["STEER_REQUEST"], 0)
    self.assertEqual(self.parser.vl["STEERING_LKA"]["STEER_TORQUE_CMD"], 0)
    if angle is not None:
      self.assertAlmostEqual(self.parser.vl["STEERING_LTA_2"]["STEER_ANGLE_CMD"], angle, delta=0.0573)

  def test_recorded_driver_takeover_cancels_request(self):
    # Route 0000006d--b94527dd80, 422.88 s: driver=212, EPS=2436, desired=115.25, measured=54.52 deg.
    self.step()
    self.assert_lta(True)
    self.step(steeringTorque=212, steeringPressed=True, steeringTorqueEps=2436, steeringAngleDeg=54.52)
    self.step()
    self.assert_lta(False, 54.52)

  def test_recorded_takeover_and_release_replay(self):
    # Exact 100 Hz inputs from segment 7, including two brief releases and the final sustained release.
    fixture = json.loads(gzip.decompress((Path(__file__).parent / "fixtures/sienna_lta_override.json.gz").read_bytes()))
    recorded_parser = CANParser("toyota_secoc_pt_generated", [("STEERING_LTA_2", 50)], 0)
    for timestamp, address, source, payload in fixture["returned_can_near_override"]:
      self.assertEqual(source, 128)  # returned bus 0 only; stock bus 2 is not evidence of our output
      recorded_parser.update([(timestamp, [(address, bytes.fromhex(payload), 0)])])
    self.assertEqual(recorded_parser.vl["STEERING_LTA_2"]["STEER_REQUEST"], 1)
    self.assertEqual(len(fixture["inputs"]), 1594)
    for frame, row in enumerate(fixture["inputs"]):
      _, self.control.latActive, self.control.actuators.steeringAngleDeg, *values = row
      state = dict(zip(fixture["fields"][3:], values, strict=True))
      self.step(**state)
      if frame % 2 == 0:
        # Driver override at 181. Quiet runs 507..591 and 1202..1243 are too short;
        # the final uninterrupted quiet run starts at 1328, so reactivation first transmits at 1428.
        active = frame < 181 or frame >= 1428
        angle = max(-94.9461, min(94.9461, state["steeringAngleDeg"] + state["steeringAngleOffsetDeg"]))
        self.assert_lta(active, None if active else angle)

  def test_release_requires_low_torque_dwell(self):
    self.step(steeringTorque=-200, steeringPressed=True)
    self.assert_lta(False, 0)
    # Dropping below the trigger is insufficient: the release threshold is strictly below 80.
    for _ in range(120):
      self.step(steeringTorque=-80, steeringPressed=False)
      self.assert_lta(False, 0)
    for _ in range(99):
      self.step(steeringTorque=-79)
      self.assert_lta(False, 0)
    self.step()
    self.assert_lta(True)

  def test_override_triggers_on_either_input_and_both_frame_phases(self):
    for torque, pressed, phase in itertools.product((0, 150, -150), (False, True), (0, 1)):
      if not torque and not pressed:
        continue
      with self.subTest(torque=torque, pressed=pressed, phase=phase):
        self.setUp()
        for _ in range(2 + phase):
          self.step()
        self.step(steeringTorque=torque, steeringPressed=pressed, steeringAngleDeg=-50, steeringAngleOffsetDeg=3)
        if phase:
          self.step()
        self.assert_lta(False, -47)

  def test_release_dwell_restarts_on_input_or_steering_pressed(self):
    for torque, pressed in ((80, False), (-80, False), (0, True), (212, True)):
      with self.subTest(torque=torque, pressed=pressed):
        self.setUp()
        self.step(steeringPressed=True)
        for _ in range(60):
          self.step(steeringPressed=False)
        self.step(steeringTorque=torque, steeringPressed=pressed)
        # A lateral-active toggle must not bypass the ongoing driver release dwell.
        for frame in range(99):
          self.control.latActive = frame > 20
          self.step(steeringTorque=0, steeringPressed=False, steeringAngleDeg=40 + frame / 10, steeringAngleOffsetDeg=-3)
          self.assert_lta(False)
        self.step()
        self.step()  # next 50 Hz message
        self.assert_lta(True)
        # Resume from the last inactive measured angle (46.8), without jumping to the 115.25-degree target.
        resumed_angle = self.parser.vl["STEERING_LTA_2"]["STEER_ANGLE_CMD"]
        self.assertGreaterEqual(resumed_angle, 46.8)
        self.assertLess(resumed_angle, 115.25)

  def test_inactive_angle_follows_measurement_with_high_mode_cap(self):
    for angle, expected in ((-120, -115), (-40, -35), (50, 55), (120, 125), (-200, -180.0366), (200, 180.0366)):
      with self.subTest(angle=angle):
        self.step(steeringPressed=True, steeringAngleDeg=angle, steeringAngleOffsetDeg=5)
        self.step()
        self.assert_lta(False, expected)

  def test_steering_rate_cut_still_applies_after_driver_release(self):
    self.step(steeringPressed=True, steeringRateDeg=600, steeringAngleDeg=5)
    for _ in range(99):
      self.step(steeringPressed=False)
      self.assert_lta(False, 5)
    for frame in range(100, 136):
      self.step()
      if frame % 2 == 0:
        self.assert_lta(frame != 132, 5 if frame == 132 else None)


class TestToyotaInterfaces(unittest.TestCase):
  def test_legacy_can_output_unchanged(self):
    # Golden traces from unmodified opendbc commit 1d94be62 (all CAN frames, including SecOC MACs).
    expected = {
      CAR.TOYOTA_SIENNA_PATCHED: ("46085e4053fec4d11e37be20079748507e88ab93839549b3c6936b072509bbd0",
                                 "bc171f9662a8a4eff83cb2b90e40a7b10ea4c696982afb162076c7a98aa0107b"),
      CAR.TOYOTA_RAV4_TSS2_2023: ("614f1aeb8121ff32799b841a0f6f3e2a9bc56e7cd160ed984d9ae9f3e6471f66",
                                 "00ddb715f1ef70b40f732e5b533119fcc6fa8da9f41800a344d076dbb1af6e07"),
    }
    for platform, hashes in expected.items():
      for varied, digest in enumerate(hashes):
        with self.subTest(platform=platform, varied=varied):
          self.assertEqual(hashlib.sha256(legacy_can_trace(platform, bool(varied))).hexdigest(), digest)

  def test_car_flags(self):
    # Angle and radar-ACC cars are always TSS2 cars
    assert not (cars_with(ToyotaFlags.ANGLE_CONTROL | ToyotaFlags.RADAR_ACC) - cars_with(ToyotaFlags.TSS2))

  def test_lta_platforms(self):
    # Only RAV4 2023 and the dedicated patched LTA Sienna use LTA/angle control
    assert cars_with(ToyotaFlags.ANGLE_CONTROL) == {CAR.TOYOTA_RAV4_TSS2_2023, CAR.TOYOTA_SIENNA_PATCHED_LTA}

  def test_eps_bypass_secoc(self):
    # Only the two patched Sienna platforms use EPS-bypassed SecOC
    assert cars_with(ToyotaFlags.EPS_BYPASS_SECOC) == {CAR.TOYOTA_SIENNA_PATCHED, CAR.TOYOTA_SIENNA_PATCHED_LTA}

    # EPS-bypass SecOC platforms are lateral-only: longitudinal remains stock
    CP = CarInterface.get_params(CAR.TOYOTA_SIENNA_PATCHED, gen_empty_fingerprint(), list(),
                                 alpha_long=False, is_release=False, docs=False)
    assert not CP.openpilotLongitudinalControl

  def test_tss2_dbc(self):
    # We make some assumptions about TSS2 platforms,
    # like looking up certain signals only in this DBC
    for car_model, dbc in DBC.items():
      if car_model.config.flags & ToyotaFlags.TSS2 and not (car_model.config.flags & ToyotaFlags.SECOC):
        assert dbc[Bus.pt] == "toyota_nodsu_pt_generated"

  def test_essential_ecus(self):
    # Asserts standard ECUs exist for each platform
    common_ecus = {Ecu.fwdRadar, Ecu.fwdCamera}
    for car_model, ecus in FW_VERSIONS.items():
      with self.subTest(car_model=car_model.value):
        present_ecus = {ecu[0] for ecu in ecus}
        missing_ecus = common_ecus - present_ecus
        assert len(missing_ecus) == 0

        # Some exceptions for other common ECUs
        if car_model not in (CAR.TOYOTA_ALPHARD_TSS2,):
          assert Ecu.abs in present_ecus

        if car_model not in (CAR.TOYOTA_MIRAI,):
          assert Ecu.engine in present_ecus

        if car_model not in (CAR.TOYOTA_PRIUS_V, CAR.LEXUS_CTH):
          assert Ecu.eps in present_ecus


class TestToyotaFingerprint(unittest.TestCase):
  def test_non_essential_ecus(self):
    # Ensures only the cars that have multiple engine ECUs are in the engine non-essential ECU list
    for car_model, ecus in FW_VERSIONS.items():
      with self.subTest(car_model=car_model.value):
        engine_ecus = {ecu for ecu in ecus if ecu[0] == Ecu.engine}
        assert (len(engine_ecus) > 1) == (car_model in FW_QUERY_CONFIG.non_essential_ecus[Ecu.engine]), \
          f"Car model unexpectedly {'not ' if len(engine_ecus) > 1 else ''}in non-essential list"

  def test_valid_fw_versions(self):
    # Asserts all FW versions are valid
    for car_model, ecus in FW_VERSIONS.items():
      with self.subTest(car_model=car_model.value):
        for fws in ecus.values():
          for fw in fws:
            assert check_fw_version(fw), fw

  # Tests for part numbers, platform codes, and sub-versions which Toyota will use to fuzzy
  # fingerprint in the absence of full FW matches:
  @fuzzy_test(max_examples=100)
  def test_platform_codes_fuzzy_fw(self, fuzzy):
    get_platform_codes(fuzzy.list(fuzzy.binary))

  def test_platform_code_ecus_available(self):
    # Asserts ECU keys essential for fuzzy fingerprinting are available on all platforms
    for car_model, ecus in FW_VERSIONS.items():
      with self.subTest(car_model=car_model.value):
        for platform_code_ecu in PLATFORM_CODE_ECUS:
          if platform_code_ecu == Ecu.eps and car_model in (CAR.TOYOTA_PRIUS_V, CAR.LEXUS_CTH,):
            continue
          if platform_code_ecu == Ecu.abs and car_model in (CAR.TOYOTA_ALPHARD_TSS2,):
            continue
          assert platform_code_ecu in [e[0] for e in ecus]

  def test_fw_format(self):
    # Asserts:
    # - every supported ECU FW version returns one platform code
    # - every supported ECU FW version has a part number
    # - expected parsing of ECU sub-versions

    for car_model, ecus in FW_VERSIONS.items():
      with self.subTest(car_model=car_model.value):
        for ecu, fws in ecus.items():
          if ecu[0] not in PLATFORM_CODE_ECUS:
            continue

          codes = dict()
          for fw in fws:
            result = get_platform_codes([fw])
            # Check only one platform code and sub-version
            assert 1 == len(result), f"Unable to parse FW: {fw}"
            assert 1 == len(list(result.values())[0]), f"Unable to parse FW: {fw}"
            codes |= result

          # Toyota places the ECU part number in their FW versions, assert all parsable
          # Note that there is only one unique part number per ECU across the fleet, so this
          # is not important for identification, just a sanity check.
          assert all(code.count(b"-") > 1 for code in codes), f"FW does not have part number: {fw} {codes}"

  def test_platform_codes_spot_check(self):
    # Asserts basic platform code parsing behavior for a few cases
    results = get_platform_codes([
      b"F152607140\x00\x00\x00\x00\x00\x00",
      b"F152607171\x00\x00\x00\x00\x00\x00",
      b"F152607110\x00\x00\x00\x00\x00\x00",
      b"F152607180\x00\x00\x00\x00\x00\x00",
    ])
    assert results == {b"F1526-07-1": {b"10", b"40", b"71", b"80"}}

    results = get_platform_codes([
      b"\x028646F4104100\x00\x00\x00\x008646G5301200\x00\x00\x00\x00",
      b"\x028646F4104100\x00\x00\x00\x008646G3304000\x00\x00\x00\x00",
    ])
    assert results == {b"8646F-41-04": {b"100"}}

    # Short version has no part number
    results = get_platform_codes([
      b"\x0235870000\x00\x00\x00\x00\x00\x00\x00\x00A0202000\x00\x00\x00\x00\x00\x00\x00\x00",
      b"\x0235883000\x00\x00\x00\x00\x00\x00\x00\x00A0202000\x00\x00\x00\x00\x00\x00\x00\x00",
    ])
    assert results == {b"58-70": {b"000"}, b"58-83": {b"000"}}

    results = get_platform_codes([
      b"F152607110\x00\x00\x00\x00\x00\x00",
      b"F152607140\x00\x00\x00\x00\x00\x00",
      b"\x028646F4104100\x00\x00\x00\x008646G5301200\x00\x00\x00\x00",
      b"\x0235879000\x00\x00\x00\x00\x00\x00\x00\x00A4701000\x00\x00\x00\x00\x00\x00\x00\x00",
    ])
    assert results == {b"F1526-07-1": {b"10", b"40"}, b"8646F-41-04": {b"100"}, b"58-79": {b"000"}}

  def test_fuzzy_excluded_platforms(self):
    # Asserts a list of platforms that will not fuzzy fingerprint with platform codes due to them being shared.
    platforms_with_shared_codes = set()
    for platform, fw_by_addr in FW_VERSIONS.items():
      car_fw = []
      for ecu, fw_versions in fw_by_addr.items():
        ecu_name, addr, sub_addr = ecu
        for fw in fw_versions:
          car_fw.append(CarParams.CarFw(ecu=ecu_name, fwVersion=fw, address=addr,
                                        subAddress=0 if sub_addr is None else sub_addr))

      CP = CarParams(carFw=car_fw)
      matches = FW_QUERY_CONFIG.match_fw_to_car_fuzzy(build_fw_dict(CP.carFw), CP.carVin, FW_VERSIONS)
      if len(matches) == 1:
        assert list(matches)[0] == platform
      else:
        # If a platform has multiple matches, add it and its matches
        platforms_with_shared_codes |= {str(platform), *matches}

    assert platforms_with_shared_codes == FUZZY_EXCLUDED_PLATFORMS, (len(platforms_with_shared_codes), len(FW_VERSIONS))
