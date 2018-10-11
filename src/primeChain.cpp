/* Copyright (C) 2012-2017 IBM Corp.
 * This program is Licensed under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *   http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License. See accompanying LICENSE file.
 */
/**
 * @file primeChain.cpp
 * @brief handling the chain of moduli
 */
#include <climits>
#include <algorithm>
#include "primeChain.h"
#include "FHEContext.h"
#include "sample.h"
#include "binio.h"

NTL_CLIENT

inline bool
operator>(const ModuliSizes::Entry& a, const ModuliSizes::Entry& b)
{ return a.first>b.first; }

ostream& operator<<(ostream& s, const ModuliSizes::Entry& e)
{
  return s << '['<< e.first << ' ' << e.second << "]\n";
}
istream& operator>>(istream& s, ModuliSizes::Entry& e)
{
  seekPastChar(s,'['); // defined in NumbTh.cpp
  s >> e.first;
  s >> e.second;
  seekPastChar(s,']');
  return s;
}
void write(ostream& s, const ModuliSizes::Entry& e)
{
  write_raw_double(s, e.first);
  e.second.write(s);
}

void read(istream& s, ModuliSizes::Entry& e)
{
  e.first = read_raw_double(s);
  e.second.read(s);
}

// initialize helper table for a given chain
void ModuliSizes::init(const std::vector<Cmodulus>& chain,
                       const IndexSet& ctxtPrimes, const IndexSet& smallPrimes)
{
  long n = (1L<<smallPrimes.card()) * ctxtPrimes.card();
  sizes.reserve(n); // allocate space
  // each entry of sizes is a pair<double,IndexSet>=(size, set-of-primes)

  // Get all subsets of smallPrimes

  sizes.push_back(make_pair(0.0,IndexSet::emptySet())); // the empty set
  long idx = 1;                      // first index that's still not set

  for (long i: smallPrimes) {   // add i to all sets upto idx-1
    double sizeOfQi = log(chain[i].getQ());
    for (long j=idx; j<2*idx; j++) {
      sizes.push_back(sizes[j-idx]); // make a copy
      sizes[j].first += sizeOfQi; // add sizeOfQi to size
      sizes[j].second.insert(i);  // add i to the set of primes
    }
    idx *= 2;
  }

  // For every i in ctxtPrimes, make a copy of
  // the above plus the interval [ctxt.first, i]

  IndexSet s; // empty set
  double intervalSize = 0.0;
  for (long i: ctxtPrimes) { // add i to all sets upto idx-1
    s.insert(i);                          // add prime to the interval
    intervalSize += log(chain[i].getQ()); // add its size to intervalSize
    for (long j=0; j<idx; j++) {
      sizes.push_back(sizes[j]); // make a copy
      long n = sizes.size()-1;
      sizes[n].first += intervalSize; // add size
      sizes[n].second.insert(s);      // add interval
    }
  }

  // Finally, sort the 'sizes' array
  std::sort(sizes.begin(), sizes.end());
}

// Find a suitable IndexSet of primes whose total size is in the
// target interval [low,high], trying to minimize the number of
// primes dropped from fromSet.
// If no IndexSet exsists that fits in the target interval, returns
// the IndexSet that gives the largest value smaller than low.
IndexSet ModuliSizes::getSet4Size(double low, double high,
                                  const IndexSet& fromSet,
                                  bool reverse) const
{
  long n = sizes.size();

  // lower_bound returns an iterator to the first element with size>=low
  auto it = std::lower_bound(sizes.begin(), sizes.end(),
                             Entry(low, IndexSet::emptySet()));
  long idx = it - sizes.begin(); // The index of this element

  long bestOption = -1;
  long bestCost = LONG_MAX;
  long ii = idx;
  for (; ii < n && sizes[ii].first <= high; ii++) {
    long setDiffSize = card(fromSet / sizes[ii].second);
    if (setDiffSize <= bestCost) {
      bestOption = ii;
      bestCost = setDiffSize;
    }
  }

  // If nothing was found, use the closest set below 'low'
  // (or above 'high' if reverse).  We actually one bit of slack,
  // examining the not just the closest set, but those sets
  // whose size is within 1 bit of the closest.
  
  if (bestOption == -1) {
    if (reverse) {
      if (ii < n) {
	double upperBound = sizes[ii].first + 1.0*log(2.0);
	for (long i=ii; i < n && sizes[i].first <= upperBound; ++i) {
	  long setDiffSize = card(fromSet / sizes[i].second);
	  if (setDiffSize < bestCost) {
	    bestOption = i;
	    bestCost = setDiffSize;
	  }
	}
      }
    }
    else {
      if (idx>0) {
	double lowerBound = sizes[idx-1].first - 1.0*log(2.0);
	for (long i=idx-1; i>=0 && sizes[i].first >= lowerBound; --i) {
	  long setDiffSize = card(fromSet / sizes[i].second);
	  if (setDiffSize < bestCost) {
	    bestOption = i;
	    bestCost = setDiffSize;
	  }
	}
      }
    }
  }

  assert(bestOption != -1); // make sure that soemthing was found

  return sizes[bestOption].second; // return the best IndexSet
}

//! Find a suitable IndexSet of primes whose total size is in the
//! target interval [low,high], trying to minimize the total number
//! of primes dropped from both from1, from2.
//! If no IndexSet exsists that fits in the target interval, returns
//! the IndexSet that gives the largest value smaller than low.
IndexSet ModuliSizes::getSet4Size(double low, double high,
                                  const IndexSet& from1, const IndexSet& from2,
                                  bool reverse) const
{
  long n = sizes.size();

  // lower_bound returns an iterator to the first element with size>=low
  auto it = std::lower_bound(sizes.begin(), sizes.end(),
                             Entry(low, IndexSet::emptySet()));
  long idx = it - sizes.begin(); // The index of this element

  long bestOption = -1;
  long bestCost = LONG_MAX;
  long ii = idx;
  for (; ii < n && sizes[ii].first <= high; ii++) {
    long setDiffSize = card(from1 / sizes[ii].second) + 
                       card(from2 / sizes[ii].second);
    if (setDiffSize <= bestCost) {
      bestOption = ii;
      bestCost = setDiffSize;
    }
  }

  // If nothing was found, use the closest set below 'low'
  // (or above 'high' if reverse).  We actually one bit of slack,
  // examining the not just the closest set, but those sets
  // whose size is within 1 bit of the closest.
  
  if (bestOption == -1) {
    if (reverse) {
      if (ii < n) {
	double upperBound = sizes[ii].first + 1.0*log(2.0);
	for (long i=ii; i < n && sizes[i].first <= upperBound; ++i) {
	  long setDiffSize = card(from1 / sizes[i].second) + 
			     card(from2 / sizes[i].second);
	  if (setDiffSize < bestCost) {
	    bestOption = i;
	    bestCost = setDiffSize;
	  }
	}
      }
    }
    else {
      if (idx>0) {
	double lowerBound = sizes[idx-1].first - 1.0*log(2.0);
	for (long i=idx-1; i>=0 && sizes[i].first >= lowerBound; --i) {
	  long setDiffSize = card(from1 / sizes[i].second) + 
			     card(from2 / sizes[i].second);
	  if (setDiffSize < bestCost) {
	    bestOption = i;
	    bestCost = setDiffSize;
	  }
	}
      }
    }
  }

  assert(bestOption != -1); // make sure that soemthing was found

  return sizes[bestOption].second; // return the best IndexSet


}

ostream& operator<<(ostream& s, const ModuliSizes& szs)
{
  return s <<'['<< szs.sizes.size()<<' '<<szs.sizes<<']';
}
istream& operator>>(istream& s, ModuliSizes& szs)
{
  long n;
  seekPastChar(s,'['); // defined in NumbTh.cpp
  s >> n;
  szs.sizes.resize(n); // allocate space
  for (long i=0; i<n; i++)
    s >> szs.sizes[i];
  seekPastChar(s,']');
  return s;
}

void ModuliSizes::write(ostream& str) const
{
  write_raw_int(str, lsize(sizes));
  for (long i=0; i<lsize(sizes); i++)
    ::write(str, sizes[i]);
}

void ModuliSizes::read(istream& str)
{
  long n = read_raw_int(str);
  sizes.resize(n); // allocate space
  for (long i=0; i<n; i++)
    ::read(str, sizes[i]);
}


// You initialize a PrimeGenerator as follows:
//    PrimeGenerator gen(len, m);
// Each call to gen.next() generates a prime p with 
// (3/4)*2^len <= p < 2^len and p = 2^k*t*m + 1,
// where t is odd and k is as large as possible.
// If no such prime is found, then an error is raised.

struct PrimeGenerator {
  long len, m;
  long k, t;

  PrimeGenerator(long _len, long _m) : len(_len), m(_m)
  {
    if (len > NTL_SP_NBITS || len < 2 || m >= NTL_SP_BOUND || m <= 0)
      Error("PrimeGenerator: bad args");

    // compute k as smallest nonnegative integer such that
    // 2^{len-2} < 2^k*m
    k = 0;
    while ((m << k) <= (1L << (len-2))) k++;

    t = 8; // with above setting for k, we have 2^{len-1}/(2^k*m) < 4,
           // so setting t = 8 will trigger a new k-value with the
           // first call to next()
  }

  long next()
  {
    // we consider all odd t in the interval 
    // [ ((3/4)*2^len-1)/(2^k*m), (2^len-1)/(2^k*m) ).
    // For k satisfyng 2^{len-2} >= 2^k*m, this interval is
    // non-empty.
    // It is equivalent to consider the interval
    // of integers [tlb, tub), where tlb = ceil(((3/4)*2^len-1)/(2^k*m))
    // and tub = ceil((2^len-1)/(2^k*m)).

    long tub = divc((1L << len)-1, m << k);

    for (;;) {

      t++;

      if (t >= tub) {
	// move to smaller value of k, reset t and tub
   
	k--;

	long klb;
	if (m%2 == 0) 
	  klb = 0;
	else
	  klb = 1;

	if (k < klb) Error("PrimeGenerator: ran out of primes");
	// we run k down to 0  if m is even, and down to 1
	// if m is odd.

	t = divc(3*(1L << (len-2))-1, m << k);
	tub = divc((1L << len)-1, m << k);
      }

      if (t%2 == 0) continue; // we only want to consider odd t

      long cand = ((t*m) << k) + 1; // = 2^k*t*m + 1

      // double check that cand is in the prescribed interval
      assert(cand >= (1L << (len-2))*3 && cand < (1L << len));

      if (ProbPrime(cand, 60)) return cand;
      // iteration count == 60 implies 2^{-120} error probability
    }

  }

};

void FHEcontext::AddSmallPrime(long q)
{
  assert(!inChain(q));
  long i = moduli.size(); // The index of the new prime in the list
  moduli.push_back( Cmodulus(zMStar, q, 0) );
  smallPrimes.insert(i);
}

void FHEcontext::AddCtxtPrime(long q)
{
  assert(!inChain(q));
  long i = moduli.size(); // The index of the new prime in the list
  moduli.push_back( Cmodulus(zMStar, q, 0) );
  ctxtPrimes.insert(i);
}

void FHEcontext::AddSpecialPrime(long q)
{
  assert(!inChain(q));
  long i = moduli.size(); // The index of the new prime in the list
  moduli.push_back( Cmodulus(zMStar, q, 0) );
  specialPrimes.insert(i);
}

//! @brief Add small primes to get target resolution
void addSmallPrimes(FHEcontext& context, long resolution)
{
  long m = context.zMStar.getM();
  if (m<=0 || m>(1<<20))// sanity checks
    Error("addSmallPrimes: m undefined or larger than 2^20");
  // NOTE: Below we are ensured that 16m*log(m) << NTL_SP_BOUND

  if (resolution<1 || resolution>10) // set to default of 3-bit resolution
    resolution = 3;

  vector<long> sizes;
  if (NTL_SP_NBITS>=60) { // make the smallest primes 40-bit primes
    sizes.push_back(40);
    sizes.push_back(40);
  }
  else if (NTL_SP_NBITS >=50) { // make the smallest primes 35-bit primes
    sizes.push_back(35);
    sizes.push_back(35);
  }
  else { // Make the smallest ones 22-bit primes
    assert(NTL_SP_NBITS >=30);
    sizes.push_back(22);
    sizes.push_back(22);
    sizes.push_back(22);
  }

  // This ensures we can express everything to given resolution.

  // use sizes 60-r, 60-2r, 60-4r,... downto the sizes above
  for (long delta=resolution; NTL_SP_NBITS-delta>sizes[0]; delta*=2)
    sizes.push_back(NTL_SP_NBITS-delta);

  // This helps to minimize the number of small primes needed
  // to express any particular resolution.
  // This could be removed...need to experiment.

  // Special cases: add also NTL_SP_NBITS-3*resolution,
  // and for resolution=1 also NTL_SP_NBITS-11
  if (NTL_SP_NBITS - 3*resolution > sizes[0])
    sizes.push_back(NTL_SP_NBITS- 3*resolution);
  if (resolution==1 && NTL_SP_NBITS-11 > sizes[0])
    sizes.push_back(NTL_SP_NBITS- 11);

  std::sort(sizes.begin(), sizes.end()); // order by size

  long last_sz = 0;
  long sz_cnt = 0;
  std::unique_ptr<PrimeGenerator> gen;
  for (long sz : sizes) {
    if (sz != last_sz) gen.reset(new PrimeGenerator(sz, m));
    long q = gen->next();
    context.AddSmallPrime(q);
    last_sz = sz;
  }
}

void addCtxtPrimes(FHEcontext& context, long nBits)
{
  // we simply add enough primes of size NTL_SP_NBITS
  // until their product is at least 2^{nBits}

  const PAlgebra& palg = context.zMStar;
  long m = palg.getM();

  double bitlen = 0;

  PrimeGenerator gen(NTL_SP_NBITS, m);

  while (bitlen < nBits) {
    long q = gen.next();
    context.AddCtxtPrime(q);
    bitlen += log2(q);
  }


}


void addSpecialPrimes(FHEcontext& context, long nDgts, 
                      bool willBeBootstrappable)
{
  const PAlgebra& palg = context.zMStar;
  long p = palg.getP();
  long m = palg.getM();
  long p2r = context.alMod.getPPowR();

  long p2e = p2r;
  if (willBeBootstrappable) { // bigger p^e for bootstrapping
    double alpha; long e, ePrime;
    RecryptData::setAlphaE(alpha,e,ePrime, context);
    p2e *= NTL::power_long(p, e-ePrime);
  }

  long nCtxtPrimes = context.ctxtPrimes.card();
  if (nDgts > nCtxtPrimes) nDgts = nCtxtPrimes; // sanity checks
  if (nDgts <= 0) nDgts = 1;

  context.digits.resize(nDgts); // allocate space

  double maxDigitLog = 0.0;
  if (nDgts>1) { // we break ciphertext into a few digits when key-switching
    double dlog = context.logOfProduct(context.ctxtPrimes)/nDgts; 
    // estimate log of each digit

    IndexSet s1;
    double logSoFar = 0.0;

    double target = dlog;
    long idx = context.ctxtPrimes.first();
    for (long i=0; i<nDgts-1; i++) { // set all digits but the last
      IndexSet s;
      while (idx <= context.ctxtPrimes.last() && (empty(s)||logSoFar<target)) {
        s.insert(idx);
	logSoFar += log(context.ithPrime(idx));
	idx = context.ctxtPrimes.next(idx);
      }
      assert (!empty(s));
      context.digits[i] = s;
      s1.insert(s);
      double thisDigitLog = context.logOfProduct(s);
      if (maxDigitLog < thisDigitLog) maxDigitLog = thisDigitLog;
      target += dlog;
    }
    // The ctxt primes that are left (if any) form the last digit
    IndexSet s = context.ctxtPrimes / s1;
    if (!empty(s)) {
      context.digits[nDgts-1] = s;
      double thisDigitLog = context.logOfProduct(s);
      if (maxDigitLog < thisDigitLog) maxDigitLog = thisDigitLog;
    }
    else { // If last digit is empty, remove it
      nDgts--;
      context.digits.resize(nDgts);
    }
  }
  else { // only one digit
    maxDigitLog = context.logOfProduct(context.ctxtPrimes);
    context.digits[0] = context.ctxtPrimes;
  }

  // Add special primes to the chain for the P factor of key-switching
  double logOfSpecialPrimes
    = maxDigitLog + log(nDgts) + log(context.stdev *2) + log(p2e);

  // we now add enough special primes so that the sum of their
  // logs is at least logOfSpecial primes

  // we first calculate nbits, which is the bit length of each
  // special prime.  This is calculated so that we don't overshoot
  // logOfSpecial primes by too much because of granularity

  double totalBits = logOfSpecialPrimes/log(2.0);
  long numPrimes = ceil(totalBits/NTL_SP_NBITS);  
  // initial estimate # of special primes
  long nbits = ceil(totalBits/numPrimes);         
  // estimated size of each special prime

  nbits++;
  // add 1 so we don't undershoot 

  if (nbits > NTL_SP_NBITS) nbits = NTL_SP_NBITS;
  // make sure nbits not too large

  // now add special primes of size nbits

  PrimeGenerator gen(nbits, m);

  double logSoFar = 0.0;
  while (logSoFar < logOfSpecialPrimes) {
    long q = gen.next();

    if (context.inChain(q)) continue;
    // nbits could equal NTL_SP_BITS or the size of one 
    // of the small primes, so we have to check for duplicates here...
    // this is not the most efficient way to do this,
    // but it doesn't make sense to optimize this any further

    context.AddSpecialPrime(q);
    logSoFar += log(q);
  }
}

void buildModChain(FHEcontext& context, long nBits, long nDgts,
                      bool willBeBootstrappable, long resolution)
{
   addSmallPrimes(context, resolution);
   addCtxtPrimes(context, nBits);
   addSpecialPrimes(context, nDgts, willBeBootstrappable);
   context.setModSizeTable();
}

