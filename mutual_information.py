from numpy import log2

TOTAL_SAMPLES = 0
TOTAL_MALWARE_SAMPLES = 0
TOTAL_BENIGN_SAMPLES = 0
MALWARE_FREQUENCY = 0
BENIGN_FREQUENCY = 0
FEATURE = "Feature Name"

print("\nMutual Information Score")

print("\nFor The Feature {}, the Appearance Frequencies are: \n\nBenign Frequency: {} / {}\nMalware Frequency: {} / {}".format(FEATURE, BENIGN_FREQUENCY, TOTAL_BENIGN_SAMPLES, MALWARE_FREQUENCY, TOTAL_MALWARE_SAMPLES))

probability_occurs = ((MALWARE_FREQUENCY + BENIGN_FREQUENCY) / TOTAL_SAMPLES)
print("\nThe Probability That {} Occurs in Both Malware and Benign Code is: {}".format(FEATURE, probability_occurs))

probability_does_not_occur = ((TOTAL_SAMPLES - (MALWARE_FREQUENCY + BENIGN_FREQUENCY)) / TOTAL_SAMPLES)
print("The Probability That {} Does Not Occur in Both Malware and Benign Code is: {}".format(FEATURE, probability_does_not_occur))

malicious_probability_occurs = (MALWARE_FREQUENCY / (MALWARE_FREQUENCY + BENIGN_FREQUENCY))
print("The Probability That The Code Sample is Malicious when {} Occurs is: {}".format(FEATURE, malicious_probability_occurs))

benign_probability_occurs = (BENIGN_FREQUENCY / (MALWARE_FREQUENCY + BENIGN_FREQUENCY))
print("The Probability That the Code Sample is Benign when {} Occurs is: {}".format(FEATURE, benign_probability_occurs))

malicious_probability_does_not_occur = ((TOTAL_MALWARE_SAMPLES - MALWARE_FREQUENCY) / (TOTAL_SAMPLES - (MALWARE_FREQUENCY + BENIGN_FREQUENCY)))
print("The Probability That the Code Sample is Malicious when {} Does Not Occur is : {}".format(FEATURE, malicious_probability_does_not_occur))

benign_probability_does_not_occur = ((TOTAL_BENIGN_SAMPLES - BENIGN_FREQUENCY) / (TOTAL_SAMPLES - (BENIGN_FREQUENCY + MALWARE_FREQUENCY)))
print("The Probability That the Code Sample is Benign when {} Does Not Occur is : {}".format(FEATURE, benign_probability_does_not_occur))

probability_class_malware = TOTAL_MALWARE_SAMPLES / TOTAL_SAMPLES

probability_class_benign = TOTAL_BENIGN_SAMPLES / TOTAL_SAMPLES

feature_rank_score = (probability_does_not_occur * ((benign_probability_does_not_occur * log2((benign_probability_does_not_occur / probability_class_benign))) + (malicious_probability_does_not_occur * log2((malicious_probability_does_not_occur / probability_class_malware))))) + (probability_occurs * ((benign_probability_occurs * (log2((benign_probability_occurs / probability_class_benign)))) + (malicious_probability_occurs * (log2((malicious_probability_occurs / probability_class_malware))))))

print("\nThe Mutual Information Score of {} is {}".format(FEATURE, feature_rank_score))