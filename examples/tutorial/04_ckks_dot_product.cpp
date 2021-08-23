#include <helib/helib.h>

using namespace std;
using namespace helib;

// To use these routines, we need to include an extra file:
#include <helib/matmul.h>

std::pair<PtxtArray, Ctxt> generate_vector(long nrOfElements,
                                           const Context& context,
                                           const PubKey& publicKey)
{
  vector<double> vector(nrOfElements, 0.0);
  for (long i = 0; i < nrOfElements; i++) {
    vector[i] = double(2ULL);
  }
  PtxtArray p(context, vector);
  Ctxt c(publicKey);
  p.encrypt(c);
  return std::pair<PtxtArray, Ctxt>{p, c};
}

void dot_product(Ctxt& c1, Ctxt& c2)
{
  c1.multiplyBy(c2);
  totalSums(c1);
}

int main(int argc, char* argv[])
{
  // The following table lists settings of m, bits, and c that yield (at least)
  // 128-bit security.  It is highly recommended to only use settings from this
  // table.
  //
  //	m	bits	c
  //	16384	119	2
  //	32768	299	3
  //	32768	239	2
  //	65536	613	3
  //	65536	558	2
  //	131072	1255	3
  //	131072	1098	2
  //	262144	2511	3
  //	262144	2234	2
  Context context =
      ContextBuilder<CKKS>().m(32 * 1024).bits(239).precision(30).c(2).build();

  cout << "securityLevel=" << context.securityLevel() << "\n";

  // Get the number of slots, n.
  // Note that for CKKS, we always have n=m/4.
  long n = context.getNSlots();

  // Construct a secret key. A secret key must be associated with a specific
  // Context, which is passed (by reference) to the constructor.  Programming
  // note: to avoid dangling pointers, the given Context object must not be
  // destroyed while any objects associated with it are still in use.
  SecKey secretKey(context);

  // Constructing a secret key does not actually do very much.  To actually
  // build a full-fledged secret key, we have to invoke the GenSecKey method.
  secretKey.GenSecKey();

  // TECHNICAL NOTE: Note the "&" in the declaration of publicKey. Since the
  // SecKey class is a subclass of PubKey, this particular PubKey object is
  // ultimately a SecKey object, and through the magic of C++ polymorphism,
  // encryptions done via publicKey will actually use the secret key, which has
  // certain advantages.  If one left out the "&", then encryptions done via
  // publicKey will NOT use the secret key.

  // To support data movement, we need to add some information to the public
  // key. This is done as follows:
  addSome1DMatrices(secretKey);

  // Recall that SecKey is a subclass of PubKey. The call to addSome1DMatrices
  // needs data stored in the secret key, but the information it computes is
  // stored in the public key.
  const PubKey& publicKey = secretKey;

  //===========================================================================
  vector<PtxtArray> ptxtArray{};
  vector<Ctxt> ctxtArray{};

  // Let's encrypt something!
  auto v1 = generate_vector(n, context, publicKey);
  ptxtArray.push_back(v1.first);
  ctxtArray.push_back(v1.second);

  auto v2 = generate_vector(n, context, publicKey);
  ptxtArray.push_back(v2.first);
  ctxtArray.push_back(v2.second);

  cout << "c.capacity=" << ctxtArray[0].capacity() << " ";
  cout << "c.errorBound=" << ctxtArray[0].errorBound() << "\n";

  //==========================================================================

  HELIB_NTIMER_START(dot_product);
  dot_product(ctxtArray[0], ctxtArray[1]);
  HELIB_NTIMER_STOP(dot_product);
  printNamedTimer(cout, "dot_product");

  cout << "c.capacity=" << ctxtArray[0].capacity() << " ";
  cout << "c.errorBound=" << ctxtArray[0].errorBound() << "\n";

  // perform dot product on plaintexts
  ptxtArray[0] *= ptxtArray[1];
  totalSums(ptxtArray[0]);

  //==========================================================================

  PtxtArray decryption(context);
  decryption.decrypt(ctxtArray[0], secretKey);

  // Decode and store the vector of means
  std::vector<double> resultArray;
  decryption.store(resultArray);

  cout << "\ndot_product=" << resultArray[0] << "\n";

  // We compute the distance between plainText (computed on plaintexts) and
  // decryptions (computed homomorphically on ciphertexts).
  // This is computed as max{ |p3[i]-pp3[i]| : i = 0..n-1 }
  double distance = Distance(ptxtArray[0], decryption);
  cout << "distance=" << distance << "\n";

  //===========================================================================

  return 0;
}