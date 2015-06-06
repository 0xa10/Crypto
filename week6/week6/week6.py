from gmpy2 import mpz, gcd
from gmpy2 import gcdext as egcd
import gmpy2
import utils

gmpy2.get_context().precision = 1000

N1 = mpz(179769313486231590772930519078902473361797697894230657273430081157732675805505620686985379449212982959585501387537164015710139858647833778606925583497541085196591615128057575940752635007475935288710823649949940771895617054361149474865046711015101563940680527540071584560878577663743040086340742855278549092581)
ciphertext = mpz(22096451867410381776306561134883418017410069787892831071731839143676135600120538004282329650473509424343946219751512256465839967942889460764542040581564748988013734864120452325229320176487916666402997509188729971690526083222067771600019329260870009579993724077458967773697817571267229951148662959627934791540)

N2 = 648455842808071669662824265346772278726343720706976263060439070378797308618081116462714015276061417569195587321840254520655424906719892428844841839353281972988531310511738648965962582821502504990264452100885281673303711142296421027840289307657458645233683357077834689715838646088239640236866252211790085787877


def main():
    # question 1, factor N1
    N1_root = gmpy2.sqrt(N1)
    N1_A = gmpy2.ceil(N1_root)
    N1_x = gmpy2.sqrt(gmpy2.square(N1_A) - N1)
    p1 = mpz(N1_A - N1_x)
    q1 = mpz(N1_A + N1_x)

    

    print "Found prime factors of N1:"
    print "p1: %d" % (p1,)
    print "q1: %d" % (q1,)

    # question 2, factor N2 where |p?q|<2^11N^1/4
    N2_root = gmpy2.sqrt(N2)
    N2_A = gmpy2.ceil(N2_root)

    for A_delta in xrange(0, (2**20)+1):
        A = N2_A + A_delta
        N2_x = gmpy2.sqrt(gmpy2.square(A) - N2)
        p2 = mpz(A - N2_x)
        q2 = mpz(A + N2_x)
        if (p2 * q2) == N2:
            break
    else:
        print "Could not factor N2"

    assert p2*q2 == N2
    print "Found prime factors of N2:"
    print "p2: %d" % (p2,)
    print "q2: %d" % (q2,)

    # question 4
    e = mpz(65537)
    phi = (p1-1)*(q1-1)
    d = gmpy2.invert(e, phi)

    plaintext = gmpy2.powmod(ciphertext, d, N1)
    plaintext_buffer = ("0" + hex(plaintext)[2:]).decode("hex")
    assert plaintext_buffer[0] == chr(0x02)
    # remove padding
    plaintext_final  = plaintext_buffer[plaintext_buffer.find(chr(0))+1:]
    print "Plaintext is: %r" % (plaintext_final,)

    

if __name__ == "__main__":
    main()