import hmac_server
import requests
import random
import time, sys

ATTACK_TIMER = 50
PICKUP_THRESHOLD = ATTACK_TIMER/1000.0 * 0.8 # 80 percent of the alleged 50ms delay

def verify_hmac(file, signature):
    resp = requests.get(r"http://localhost:9000/test", {'file': file, 'signature' : signature})
    if resp.status_code == 200:
        return True
    elif resp.status_code == 500:
        return False
    else:
        raise Exception(resp.text)

def time_verify(file, signature):
    start = time.time()
    verify_hmac(file, signature)
    return time.time() - start

def avg(l):
    return sum(l)/float(len(l))


def main(argv):
    import threading
    threading.Thread(target = hmac_server.main, args = (["", "slow", str(ATTACK_TIMER), "AAA"],)).start()

    iterations = 0
    target_msg = "Hello\x03\x00\x00\x00"
    signature = ""
    [time_verify(target_msg, "\x00".ljust(20,"\x00").encode("hex")) for i in range(3)]
    prev_time = avg([time_verify(target_msg, "\x00".ljust(20,"\x00").encode("hex")) for i in range(5)]) # calibrate, if first byte is zero this might be an issue but this is unlikely
    print "Starting..."
    while len(signature) < 20:
        for c in range(256):
        #for c in random.shuffle(range(256)): # random optimization?
            iterations += 1
            sig_test = (signature + chr(c)).ljust(20,"\x00")
            current_time = time_verify(target_msg, sig_test.encode("hex"))
            print "Request took %f seconds, baseline of %f" % (current_time, prev_time)
            if current_time > prev_time + PICKUP_THRESHOLD:
                # verify correctness
                print "Found candidate %s, verifying..." % (chr(c).encode("hex"))
                if not (avg([time_verify(target_msg, sig_test.encode("hex")) for i in range(3)]) > prev_time + PICKUP_THRESHOLD):
                    # whoops nope
                    print "Wrong guess, continuing..."
                    continue
                print "Confirmed hash byte %s" % (chr(c).encode("hex"))
                signature += chr(c)
                prev_time = current_time
                break
        else:
            print "Failed to find current hash byte." 
            # here perhaps retry with lower threshold?
            raise Exception("Failed")
    assert verify_hmac(target_msg, signature.encode("hex"))
    print "Managed to verify msg %r with SHA1-HMAC %s, took %d iterations (avg. %d per byte)" % (target_msg, signature.encode("hex"), iterations, iterations / 8)
    raw_input()

if __name__ == "__main__":
    main(sys.argv)
