import hmac_server
import requests
import random
import time, sys

ATTACK_TIMER = 20
SENSITIVITY = 8
PICKUP_THRESHOLD = (ATTACK_TIMER - SENSITIVITY)/1000.0 

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
    #import threading
    #threading.Thread(target = hmac_server.main, args = (["", "slow", str(ATTACK_TIMER), "AAA"],)).start()

    iterations = 0
    target_msg = "Hello!"
    signature = ""
    if len(argv) > 1:
        target_msg = argv[1]
    if len(argv) > 2:
        print "Using hint %s" % (argv[2],)
        signature = argv[2].decode("hex")        

    print "Calibrating..."
    [time_verify(target_msg, "\x00".ljust(20,"\x00").encode("hex")) for i in range(3)]
    prev_time = avg([time_verify(target_msg, signature.ljust(20,"\x00").encode("hex")) for i in range(5)]) # calibrate, if first byte is zero this might be an issue but this is unlikely
    print "Starting, target message is: %r ..." % (target_msg,)
    guessed = False
    while len(signature) < 20:
        max_guess = (0, -1)
        for c in range(256):
        #for c in random.shuffle(range(256)): # random optimization?
            iterations += 1
            sig_test = (signature + chr(c)).ljust(20,"\x00")
            current_time = time_verify(target_msg, sig_test.encode("hex"))
            print "Guess %s took %f seconds, baseline of %f, difference of %dms" % (chr(c).encode("hex"), current_time, prev_time, (current_time-prev_time)*1000)
            max_guess = max(max_guess, (c, (current_time-prev_time)), key = lambda x : x[1])
            if current_time > prev_time + PICKUP_THRESHOLD:
                # verify correctness
                print "Found candidate %s, verifying..." % (chr(c).encode("hex"))
                avg_time = avg([time_verify(target_msg, sig_test.encode("hex")) for i in range(3)])
                print "Average difference - %dms" % ((avg_time - prev_time) * 1000,)
                if not (avg_time > prev_time + PICKUP_THRESHOLD):
                    # whoops nope
                    print "Wrong guess, continuing..."
                    continue
                print "Confirmed hash byte %s, realigning" % (chr(c).encode("hex"))
                signature += chr(c)
                prev_time = avg([time_verify(target_msg, sig_test.encode("hex")) for i in range(3)])
                break
        else:
            if guessed:
                raise Exception("Failed")
            c = max_guess[0]
            print "Failed to find current hash byte, using %s" % (chr(c).encode("hex"))
            signature += chr(c)
            guessed = True
    assert verify_hmac(target_msg, signature.encode("hex"))
    print "Managed to verify msg %r" % (target_msg,)
    print "SHA1-HMAC: %s" % (signature.encode("hex"),)
    print "Took %d iterations (avg. %d per byte, %d%% efficiency)" % (iterations, iterations / 20, iterations / (20 / 128 * 100.0))

    return

if __name__ == "__main__":
    main(sys.argv)
