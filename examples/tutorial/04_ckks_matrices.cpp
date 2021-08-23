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

std::pair<vector<PtxtArray>, vector<Ctxt>> generate_matrix(
    long nrOfElements,
    long nrOfRows,
    const Context& context,
    const PubKey& publicKey)
{
  cout << "generating matrix \n";
  vector<PtxtArray> ptxtArray{};
  ptxtArray.reserve(nrOfRows);
  vector<Ctxt> ctxtArray{};
  ctxtArray.reserve(nrOfRows);

  for (long i = 0; i < nrOfRows; i++) {
    cout << "generating vector: " << i << " + encryption \n";

    auto pair = generate_vector(nrOfElements, context, publicKey);
    ptxtArray.push_back(pair.first);
    ctxtArray.push_back(pair.second);
  }
  return std::pair<vector<PtxtArray>, vector<Ctxt>>{ptxtArray, ctxtArray};
}

void dot_product(Ctxt& c1, Ctxt& c2)
{
  c1.multiplyBy(c2);
  totalSums(c1);
}

void matrix_multiplication(vector<Ctxt>& m1, vector<Ctxt>& m2)
{
  assertEq(m1.size(), m2.size(), "Matrix M1 and M2 are not of the same size!");

  vector<Ctxt> res{};
  res.reserve(m1.size());

  for (long col = 0; col < m1.size(); col++) {
    for (long row = 0; row < m1.size(); row++) {
      Ctxt m1VecCopyAtPositionCol = m1[col];
      Ctxt m2VecCopyAtPositionRow = m2[row];

      // Current Problem -> dot_product doesn't return a value but a vector
      // containing the resulting value at each position
      // TOOD: find a way to extract the resulting value from the dot_product
      // operation and put it into a new vector

      dot_product(m1VecCopyAtPositionCol, m2VecCopyAtPositionRow);
      // res.push_back(m1VecCopyAtPositionCol);
    }
  }
}

/*

M = 1 2 M(transposed) => M_t = 1 3
    3 4                      2 4

M' = 2 1 M'(transposed) => M'_t = 2 4
     4 3                          1 3

M'_t * M = 4 10


*/

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

  // Let's encrypt something!
  // generate first 2x2 matrix
  long nrOfRows = 2ULL;
  auto m1 = generate_matrix(2ULL, nrOfRows, context, publicKey);
  vector<PtxtArray> ptxtArray1 = m1.first;
  vector<Ctxt> ctxtArray1 = m1.second;

  // generate second 2x2 matrix
  auto m2 = generate_matrix(2ULL, nrOfRows, context, publicKey);
  vector<PtxtArray> ptxtArray2 = m2.first;
  vector<Ctxt> ctxtArray2 = m2.second;

  cout << "c1.capacity=" << ctxtArray1[0].capacity() << " ";
  cout << "c1.errorBound=" << ctxtArray1[0].errorBound() << "\n";
  cout << "c2.capacity=" << ctxtArray2[0].capacity() << " ";
  cout << "c2.errorBound=" << ctxtArray2[0].errorBound() << "\n";

  //==========================================================================
  // MATRIX MULTIPLICATION

  HELIB_NTIMER_START(matrix_multiplication);
  matrix_multiplication(ctxtArray1, ctxtArray2);
  HELIB_NTIMER_STOP(matrix_multiplication);
  printNamedTimer(cout, "matrix_multiplication");

  cout << "c1.capacity=" << ctxtArray1[0].capacity() << " ";
  cout << "c1.errorBound=" << ctxtArray1[0].errorBound() << "\n";
  cout << "c2.capacity=" << ctxtArray2[0].capacity() << " ";
  cout << "c2.errorBound=" << ctxtArray2[0].errorBound() << "\n";

  //==========================================================================

  vector<PtxtArray> decryptions(nrOfRows, PtxtArray(context));
  for (long i = 0; i < nrOfRows; i++) {
    decryptions[i].decrypt(ctxtArray1[i], secretKey);

    // Decode and store the vector of means
    std::vector<double> resultArray;
    decryptions[i].store(resultArray);

    cout << "\nresult: size=" << nrOfRows << "x" << ctxtArray1.size()
         << " value=" << resultArray[0] << "\n";

    // We compute the distance between plainText (computed on plaintexts) and
    // decryptions (computed homomorphically on ciphertexts).
    // This is computed as max{ |p3[i]-pp3[i]| : i = 0..n-1 }
    double distance = Distance(ptxtArray1[i], decryptions[i]);
    cout << "distance=" << distance << "\n";
  }

  //===========================================================================

  return 0;
}