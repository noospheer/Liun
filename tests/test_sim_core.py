"""Tests for simulation core: clock, mock Liu channel, message bus."""

import random
import pytest
from sim.core.clock import SimClock
from sim.core.mock_liu import MockLiuChannel, mac_tag, _psk_extract_mac_keys
from sim.core.message_bus import SimMessageBus, AdversaryHook, Message


class TestSimClock:

    def test_initial_tick(self):
        c = SimClock()
        assert c.tick == 0

    def test_advance(self):
        c = SimClock()
        c.advance(5)
        assert c.tick == 5

    def test_scheduled_event_fires(self):
        c = SimClock()
        results = []
        c.schedule(3, lambda: results.append('fired'))
        assert results == []
        c.advance(2)
        assert results == []
        c.advance(1)
        assert results == ['fired']

    def test_multiple_events_ordered(self):
        c = SimClock()
        results = []
        c.schedule(2, lambda: results.append('b'))
        c.schedule(1, lambda: results.append('a'))
        c.schedule(3, lambda: results.append('c'))
        c.advance(3)
        assert results == ['a', 'b', 'c']

    def test_events_at_same_tick_fifo(self):
        c = SimClock()
        results = []
        c.schedule(1, lambda: results.append('first'))
        c.schedule(1, lambda: results.append('second'))
        c.advance(1)
        assert results == ['first', 'second']

    def test_schedule_at_absolute(self):
        c = SimClock()
        c.advance(5)
        results = []
        c.schedule_at(8, lambda: results.append('at_8'))
        c.advance(3)
        assert results == ['at_8']

    def test_run_until_idle(self):
        c = SimClock()
        results = []

        def chain():
            results.append(c.tick)
            if c.tick < 5:
                c.schedule(2, chain)

        c.schedule(1, chain)
        ticks = c.run_until_idle()
        assert results == [1, 3, 5]
        assert c.pending_events == 0

    def test_event_with_args(self):
        c = SimClock()
        results = []
        c.schedule(1, lambda x, y: results.append(x + y), 3, 4)
        c.advance(1)
        assert results == [7]


class TestMockLiuChannel:

    def _make_psk(self, seed=42):
        r = random.Random(seed)
        return bytes(r.getrandbits(8) for _ in range(256))

    def test_channel_creation(self):
        psk = self._make_psk()
        ch = MockLiuChannel(1, 2, psk)
        assert ch.node_a == 1
        assert ch.node_b == 2
        assert ch.active
        assert ch.channel_id == (1, 2)

    def test_key_generation(self):
        psk = self._make_psk()
        ch = MockLiuChannel(1, 2, psk)
        bits = ch.generate_key_bits(128)
        assert len(bits) == 16  # 128/8
        assert ch.total_bits_generated == 128

    def test_key_generation_deterministic(self):
        psk = self._make_psk()
        ch1 = MockLiuChannel(1, 2, psk)
        ch2 = MockLiuChannel(1, 2, psk)
        assert ch1.generate_key_bits(256) == ch2.generate_key_bits(256)

    def test_mac_authenticate_verify(self):
        psk = self._make_psk()
        ch = MockLiuChannel(1, 2, psk)
        data = [100, 200, 300]
        tag = ch.authenticate(data, run_idx=0)
        assert ch.verify_mac(data, tag, run_idx=0)
        # Wrong data fails
        assert not ch.verify_mac([100, 200, 301], tag, run_idx=0)

    def test_mac_is_real_gf61(self):
        """MAC uses real polynomial evaluation over GF(M61)."""
        psk = self._make_psk()
        r, s = _psk_extract_mac_keys(psk, 0)
        data = [5, 3, 1]
        tag = mac_tag(data, r, s)
        # Manual: poly_eval([5,3,1], r) + s mod M61
        from liun.gf61 import poly_eval, M61
        expected = (poly_eval(data, r) + s) % M61
        assert tag == expected

    def test_closed_channel_rejects(self):
        psk = self._make_psk()
        ch = MockLiuChannel(1, 2, psk)
        ch.close()
        with pytest.raises(RuntimeError):
            ch.generate_key_bits(8)

    def test_advance_run(self):
        psk = self._make_psk()
        ch = MockLiuChannel(1, 2, psk)
        data = [42, 7]
        tag0 = ch.authenticate(data, run_idx=0)
        ch.advance_run()
        tag1 = ch.authenticate(data)  # uses run_idx=1
        assert tag0 != tag1  # different keys


class TestSimMessageBus:

    def test_send_and_deliver(self):
        clock = SimClock()
        bus = SimMessageBus(clock)
        received = []
        bus.register_handler(2, lambda msg: received.append(msg))
        bus.send(1, 2, 'hello', {'text': 'hi'})
        clock.advance(1)
        assert len(received) == 1
        assert received[0].src == 1
        assert received[0].payload['text'] == 'hi'

    def test_delivery_delay(self):
        clock = SimClock()
        bus = SimMessageBus(clock, default_delay=3)
        received = []
        bus.register_handler(2, lambda msg: received.append(msg))
        bus.send(1, 2, 'hello', {})
        clock.advance(2)
        assert len(received) == 0
        clock.advance(1)
        assert len(received) == 1

    def test_broadcast(self):
        clock = SimClock()
        bus = SimMessageBus(clock)
        received = {2: [], 3: [], 4: []}
        for nid in received:
            bus.register_handler(nid, lambda msg, n=nid: received[n].append(msg))
        bus.register_handler(1, lambda msg: None)
        bus.broadcast(1, 'announce', {'data': 42})
        clock.advance(1)
        for nid in [2, 3, 4]:
            assert len(received[nid]) == 1

    def test_adversary_hook_observe(self):
        clock = SimClock()
        bus = SimMessageBus(clock)
        observed = []

        class Observer(AdversaryHook):
            def on_send(self, msg):
                observed.append(msg.payload.copy())
                return msg

        bus.add_hook(Observer())
        bus.register_handler(2, lambda msg: None)
        bus.send(1, 2, 'secret', {'key': 42})
        clock.advance(1)
        assert len(observed) == 1
        assert observed[0]['key'] == 42

    def test_adversary_hook_drop(self):
        clock = SimClock()
        bus = SimMessageBus(clock)
        received = []

        class Dropper(AdversaryHook):
            def on_send(self, msg):
                return None  # drop all

        bus.add_hook(Dropper())
        bus.register_handler(2, lambda msg: received.append(msg))
        bus.send(1, 2, 'hello', {})
        clock.advance(1)
        assert len(received) == 0

    def test_adversary_hook_modify(self):
        clock = SimClock()
        bus = SimMessageBus(clock)
        received = []

        class Modifier(AdversaryHook):
            def on_send(self, msg):
                msg.payload['injected'] = True
                return msg

        bus.add_hook(Modifier())
        bus.register_handler(2, lambda msg: received.append(msg))
        bus.send(1, 2, 'data', {'value': 1})
        clock.advance(1)
        assert received[0].payload['injected'] is True

    def test_audit_log(self):
        clock = SimClock()
        bus = SimMessageBus(clock)
        bus.register_handler(2, lambda msg: None)
        bus.register_handler(3, lambda msg: None)
        bus.send(1, 2, 'a', {})
        bus.send(1, 3, 'b', {})
        clock.advance(1)
        assert bus.delivered_count == 2
        assert len(bus.audit_log) == 2

    def test_messages_between(self):
        clock = SimClock()
        bus = SimMessageBus(clock)
        bus.register_handler(1, lambda msg: None)
        bus.register_handler(2, lambda msg: None)
        bus.register_handler(3, lambda msg: None)
        bus.send(1, 2, 'a', {})
        bus.send(2, 1, 'b', {})
        bus.send(1, 3, 'c', {})
        clock.advance(1)
        msgs = bus.messages_between(1, 2)
        assert len(msgs) == 2
