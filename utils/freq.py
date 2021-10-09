from collections import Counter

freq_dict = {ord(" "): 0.06,
             ord("e"): 0.13, ord("E"): 0.03,
             ord("t"): 0.09, ord("T"): 0.09,
             ord("a"): 0.08, ord("A"): 0.08,
             ord("o"): 0.07, ord("O"): 0.07,
             ord("i"): 0.07, ord("I"): 0.07,
             ord("n"): 0.07, ord("N"): 0.07,
             ord("s"): 0.06, ord("S"): 0.06,
             ord("h"): 0.06, ord("H"): 0.06,
             ord("r"): 0.06, ord("R"): 0.06,
             ord("d"): 0.04, ord("D"): 0.04,
             ord("l"): 0.04, ord("L"): 0.04,
             ord("c"): 0.03, ord("C"): 0.03,
             ord("u"): 0.03, ord("U"): 0.03}

bigram_freq_dict = {(ord("T"), ord("h")): 0.25,
                    (ord("t"), ord("h")): 0.25,
                    (ord("T"), ord("H")): 0.25,
                    (ord("E"), ord("r")): 0.23,
                    (ord("e"), ord("r")): 0.23,
                    (ord("E"), ord("R")): 0.23,
                    (ord("O"), ord("n")): 0.21,
                    (ord("o"), ord("n")): 0.21,
                    (ord("O"), ord("N")): 0.21}

def tally_freqs(counts, dic):
    return [counts[b] * dic[b] for b in counts if b in dic]

def score_unigrams(byte_list):
    freqs = Counter(byte_list)
    return sum(tally_freqs(freqs, freq_dict))
    
def score_bigrams(byte_list):
    byte_list_len = len(byte_list)
    bigrams_list = [(byte_list[i], byte_list[i+1]) for i in range(byte_list_len - 1)]
    freqs = Counter(bigrams_list)
    return sum(tally_freqs(freqs, bigram_freq_dict))

def score(byte_list):
    uni_score = score_unigrams(byte_list)
    bi_score = score_bigrams(byte_list)
    return uni_score + bi_score
