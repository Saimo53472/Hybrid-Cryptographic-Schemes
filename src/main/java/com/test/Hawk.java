package com.test;

import javacard.framework.*;
import javacard.security.*;

class Hawk {
    // Parameters
    private short logn;
    private short n;
    private static final short Q = 18433;
    private static final short R2 = 806;
    private short saltLen;
    private short maxXnorm;
    private RandomData random;
    private static final short[] GM = new short[] {
            4564, 17110, 12162, 16208, 10701, 9705, 3451, 5078,
            12400, 10202, 8245, 13131, 4631, 3492, 17179, 5622,
            5537, 3399, 2485, 9938, 345, 14064, 10152, 789,
            5092, 15713, 12632, 6516, 16107, 2314, 15385, 17281,
            383, 5515, 5019, 13218, 3293, 4728, 9704, 14263,
            4417, 218, 16011, 2568, 5635, 8516, 18352, 12887,
            13102, 15257, 14316, 12813, 8886, 11051, 13356, 15353,
            12059, 6880, 17926, 11710, 8052, 1737, 16384, 18094,
            3410, 14787, 13788, 14210, 2656, 17550, 7950, 4311,
            18150, 4973, 11548, 7848, 15326, 15517, 97, 11648,
            17990, 17685, 10847, 14695, 282, 1558, 6535, 10743,
            2399, 181, 10165, 8051, 12204, 18401, 13377, 7233,
            10892, 15728, 15002, 11766, 8462, 15245, 12420, 8613,
            5053, 12360, 17415, 12678, 4606, 870, 8429, 9572,
            6542, 1892, 4008, 17045, 371, 10155, 819, 15114,
            1522, 13638, 16576, 17586, 16840, 7671, 13873, 12065,
            7433, 7599, 2497, 5298, 16406, 3443, 9437, 6905,
            14589, 17851, 209, 17496, 1698, 7028, 4444, 8211,
            9159, 16089, 16741, 9085, 2658, 4488, 8650, 3995,
            6532, 11903, 508, 192, 4039, 17347, 12742, 6993,
            14812, 17645, 4527, 695, 8380, 16230, 2153, 3136,
            2133, 4725, 9230, 13213, 6548, 18005, 6108, 16097,
            16952, 13519, 16207, 12802, 16047, 7081, 12818, 8328,
            17091, 8927, 9558, 9273, 9301, 10337, 11142, 5082,
            11846, 15508, 17108, 8498, 16135, 3776, 6752, 12857,
            3590, 486, 3056, 4203, 10364, 17125, 14532, 3025,
            18386, 12029, 1983, 7426, 13553, 623, 6269, 15287,
            16399, 12294, 6987, 8011, 1378, 14019, 3042, 3472,
            4734, 12820, 16363, 7781, 3644, 16472, 3523, 14104,
            11521, 18288, 13956, 4549, 6314, 16320, 16373, 16203,
            15299, 7524, 9080, 15914, 17765, 12520, 5829, 13379,
            9482, 7938, 760, 13350, 9526, 15502, 16160, 6398,
            7067, 1655, 3428, 7827, 10564, 1235, 10800, 8291,
            15614, 14755, 8732, 3010, 12821, 7168, 8131, 1912,
            8093, 10461, 12301, 11616, 13947, 8029, 15138, 8334,
            13345, 13462, 7201, 11285, 8232, 5869, 5652, 8087,
            9232, 151, 5425, 15984, 9061, 10972, 874, 6136,
            9299, 4966, 10442, 5398, 6605, 14398, 7625, 7091,
            10974, 14743, 6836, 17243, 504, 7883, 10503, 12533,
            3111, 13658, 1303, 6153, 12791, 335, 16064, 6652,
            14432, 10970, 558, 5436, 300, 13031, 12835, 7899,
            8435, 7252, 2970, 12879, 2786, 16438, 16584, 2204,
            5974, 6467, 7971, 14624, 9637, 9448, 18144, 7293,
            18121, 10042, 1398, 12430, 157, 6881, 18084, 12060,
            5783, 444, 14853, 7936, 13337, 10411, 4401, 12549,
            17699, 1174, 1162, 5374, 3796, 709, 1424, 8521,
            2238, 991, 9114, 15056, 4900, 16221, 731, 18419,
            14885, 1707, 11644, 7594, 14783, 4281, 12810, 5277,
            10528, 15155, 16633, 13979, 5573, 7912, 15085, 4250,
            13224, 11094, 1717, 11970, 4689, 11787, 613, 14891,
            6892, 1734, 15910, 17044, 1022, 16497, 7473, 4421,
            17061, 2094, 17491, 14013, 1872, 13480, 10045, 17585,
            1562, 10460, 12143, 11266, 2168, 15769, 3047, 7683,
            14260, 9889, 14090, 14179, 4404, 11389, 11461, 4622,
            18349, 14047, 7466, 13272, 5005, 12487, 615, 1829,
            13229, 15305, 3467, 11180, 2855, 8191, 3868, 9735,
            18383, 13189, 933, 7900, 18340, 17527, 4316, 14694,
            5680, 9549, 15669, 5777, 17938, 7070, 11080, 4478,
            1466, 10714, 15409, 8001, 7888, 3707, 14283, 7140,
            3046, 14214, 15419, 16423, 18200, 10217, 10615, 18381,
            13138, 1337, 8483, 7125, 6741, 10966, 18359, 4036,
            11656, 2954, 5907, 1652, 12095, 11393, 12093, 6022,
            11472, 6513, 15239, 12291, 16914, 3635, 2907, 373,
            12897, 8503, 16298, 8337, 10348, 11023, 8932, 5553,
            12984, 11729, 9882, 13024, 556, 65, 10270, 4317,
            14404, 9508, 9191, 9860, 14257, 11049, 13040, 14653,
            13038, 9282, 10349, 4492, 6555, 9154, 8558, 14991,
            4583, 3619, 379, 13206, 11105, 7100, 15820, 14978,
            7277, 12620, 3196, 11513, 7268, 16100, 46, 12935,
            10191, 4142, 9281, 11926, 14900, 14340, 16894, 5224,
            9309, 13388, 13942, 3818, 2937, 7206, 14135, 15212,
            7925, 1689, 8800, 1294, 5524, 14570, 16368, 11992,
            9491, 4458, 3910, 11928, 13598, 1656, 3586, 8177,
            13056, 2322, 16649, 1648, 14699, 18328, 1843, 116,
            10016, 4221, 3330, 2710, 5358, 11169, 13567, 1354,
            8715, 3439, 8805, 5505, 10680, 17825, 14534, 8396,
            4185, 3904, 8543, 2358, 13314, 13160, 14784, 16183,
            3842, 13644, 17524, 1253, 13782, 16530, 12687, 15971,
            13700, 17515, 2420, 10494, 7049, 8615, 15561, 10671,
            10485, 1060, 1583, 2340, 6599, 16718, 5525, 8039,
            12196, 15350, 10577, 8497, 16786, 10118, 13406, 2164,
            696, 7375, 3971, 630, 13829, 4501, 10704, 8545,
            8124, 10763, 4718, 6718, 13636, 11540, 16886, 2173,
            13510, 4961, 9652, 3648, 3009, 16232, 2469, 3836,
            4933, 3461, 12281, 13205, 11756, 13442, 4041, 4285,
            3661, 16043, 9473, 11418, 13814, 10301, 5454, 10915,
            8727, 17232, 13005, 3609, 9965, 5508, 3913, 10768,
            11368, 3716, 15705, 10290, 10822, 12073, 8935, 4393,
            3878, 18157, 11691, 13998, 11637, 16445, 17690, 4654,
            12911, 9234, 2765, 6125, 12586, 12014, 18046, 2176,
            17540, 7355, 811, 12063, 17878, 11837, 8513, 13958,
            16653, 12390, 3722, 4745, 7749, 8299, 2499, 10669,
            16214, 3951, 15969, 375, 13937, 18040, 11638, 9914,
            16136, 15678, 7102, 12699, 9368, 15152, 16159, 12929,
            14186, 13925, 6623, 7438, 5741, 16684, 153, 14572,
            14261, 3358, 14440, 14021, 15097, 18043, 12112, 10964,
            5242, 13012, 9833, 1249, 16386, 5032, 2437, 10065,
            1738, 3850, 11, 1891, 3970, 7161, 7025, 17895,
            6303, 14429, 12523, 17941, 6931, 5087, 11127, 10882,
            13926, 16149, 7788, 11652, 8944, 913, 15223, 6189,
            9511, 2869, 10910, 8768, 6262, 5705, 16606, 5986,
            10784, 2189, 14068, 10397, 14897, 15500, 15844, 5698,
            5743, 3622, 853, 14256, 9576, 2313, 15227, 16931,
            3810, 1440, 6324, 6309, 3400, 6365, 10288, 15790,
            16146, 5667, 10602, 11119, 5700, 7960, 4236, 2617,
            12801, 8757, 1131, 5072, 16068, 17394, 1735, 5010,
            2908, 12275, 3985, 1361, 17206, 13615, 12942, 9536,
            12505, 6468, 8129, 14974, 2983, 1708, 11802, 7944,
            17712, 8436, 5712, 3320, 13774, 13479, 9887, 17235,
            4487, 3873, 3645, 9941, 16825, 13471, 8623, 14435,
            5656, 396, 7269, 9569, 935, 13271, 13889, 18167,
            6320, 14000, 40, 15255, 4382, 7607, 3761, 8098,
            15702, 11450, 2666, 7539, 13722, 2864, 10120, 7018,
            11627, 8023, 14190, 6234, 15359, 2757, 11647, 6434,
            1917, 14513, 7362, 10475, 985, 82, 12956, 10267,
            10798, 2920, 535, 8185, 17135, 16491, 6525, 2321,
            11245, 14410, 9521, 11291, 4326, 4683, 2594, 16946,
            12878, 3561, 9648, 11339, 9944, 13628, 14996, 14086,
            16837, 8831, 12823, 12539, 2930, 16057, 11685, 16318,
            11722, 14300, 10574, 9657, 17379, 8165, 18193, 635,
            17483, 10962, 17727, 2636, 16666, 1219, 8272, 2691,
            15755, 15534, 2783, 17598, 9028, 5299, 7757, 11350,
            9421, 803, 16276, 4555, 2408, 15134, 13315, 6629,
            2575, 12004, 16466, 17109, 14006, 9793, 17355, 17445,
            9993, 6970, 13713, 6344, 17481, 5591, 17027, 2952,
            268, 827, 1635, 12955, 8609, 13704, 8571, 3820,
            15205, 13149, 13046, 12333, 8005, 13766, 18367, 7087,
            5414, 14093, 14734, 10939, 12282, 6674, 3811, 13342
    };

    static final short[] iGM = new short[]{
        2282, 9878, 10329, 12352, 15894, 7491, 4364, 3866,
        15622, 627, 16687, 6901, 2651, 5094, 13332, 12233,
        576, 1524, 17276, 1163, 15175, 12117, 1360, 15887,
        8822, 13357, 11401, 9044, 13464, 7974, 7517, 6448,
        9386, 10241, 8348, 14407, 12578, 9470, 14993, 3187,
        1540, 11755, 3691, 13990, 2810, 11275, 1588, 11882,
        2773, 9257, 14175, 6399, 17149, 1211, 18324, 7008,
        2085, 13581, 16069, 7570, 11824, 6707, 6459, 9025,
        3184, 2280, 5381, 10013, 9640, 10145, 11614, 17672,
        10876, 8807, 4139, 9031, 694, 16429, 17487, 15162,
        13647, 5002, 17998, 16130, 12094, 509, 12253, 6690,
        4910, 12223, 1594, 14202, 12550, 10932, 10569, 12987,
        5600, 2528, 16, 12331, 5191, 4134, 9126, 8017,
        3845, 5949, 17654, 18292, 1869, 3793, 374, 9438,
        12609, 9168, 1458, 10770, 14509, 12659, 6730, 9358,
        7061, 14458, 9658, 17105, 11328, 11539, 1823, 16728,
        15234, 10353, 10682, 13670, 11758, 18053, 14464, 13692,
        2527, 6302, 12173, 334, 10476, 13893, 14671, 1567,
        1115, 1030, 10273, 15276, 6942, 11455, 9289, 3456,
        11381, 7455, 10197, 16611, 5326, 1035, 12023, 16066,
        16697, 16912, 2207, 17744, 5211, 5723, 12286, 1017,
        1573, 6082, 8905, 2440, 14720, 8225, 3202, 9240,
        7704, 11167, 654, 13251, 7115, 16905, 18190, 16638,
        2788, 15057, 16545, 1149, 14184, 9879, 10679, 12510,
        15892, 12862, 4048, 4566, 4580, 13654, 4753, 671,
        14269, 12024, 5676, 1193, 12032, 1113, 2457, 9957,
        1168, 15379, 214, 15159, 2610, 13818, 6854, 8150,
        16865, 8140, 10318, 14243, 8869, 6953, 394, 11027,
        5720, 12062, 543, 7197, 18337, 18179, 3265, 15167,
        7219, 14108, 16189, 17104, 4674, 846, 1172, 4637,
        5111, 16211, 14919, 17584, 9685, 9112, 291, 1922,
        5764, 4498, 7495, 10230, 15784, 7968, 5417, 5500,
        6440, 13967, 3705, 13259, 5048, 10284, 4965, 2768,
        9030, 7763, 7399, 9976, 3071, 1597, 5960, 12697,
        15422, 3170, 3520, 3169, 17607, 6263, 16956, 12605,
        16415, 37, 12950, 5846, 5654, 4975, 8548, 11864,
        26, 3909, 4108, 9333, 1005, 1507, 11326, 16910,
        14863, 2075, 7363, 14489, 5216, 1512, 13076, 17700,
        16194, 12893, 14898, 9464, 6328, 1382, 4442, 15593,
        11086, 16275, 453, 9263, 14483, 8750, 2622, 25,
        4349, 16499, 5121, 7789, 12843, 7483, 1564, 2602,
        8302, 8909, 2973, 6714, 11797, 14700, 2193, 42,
        16122, 3486, 3522, 16231, 2127, 11388, 4272, 11303,
        5375, 7693, 1332, 17349, 12800, 3145, 13203, 17652,
        424, 4194, 11693, 17497, 2210, 471, 17386, 686,
        7006, 5480, 968, 17922, 9911, 10478, 17566, 14987,
        1771, 8910, 3323, 6872, 12448, 8358, 12886, 11821,
        16308, 1674, 14477, 6430, 2227, 900, 1639, 13169,
        6578, 12028, 7076, 1825, 14636, 12611, 8363, 1774,
        7, 8851, 1106, 15983, 10905, 13876, 8721, 17314,
        4956, 17721, 8862, 16535, 15746, 17852, 17846, 367,
        2942, 7016, 4011, 2548, 14465, 1790, 18211, 6325,
        12403, 9391, 5776, 9138, 12218, 17734, 13412, 156,
        5570, 9361, 13709, 4398, 11121, 5231, 5983, 15446,
        17331, 10141, 10214, 17040, 2777, 16948, 14807, 4999,
        5267, 2799, 2701, 18283, 15715, 18154, 12948, 11217,
        15107, 10401, 9049, 2821, 6140, 8565, 11604, 7661,
        2950, 3965, 5275, 18181, 595, 15015, 1845, 12946,
        5671, 5404, 11234, 5914, 15734, 13212, 15950, 4567,
        15365, 17996, 12947, 4686, 10441, 6504, 9141, 13817,
        5173, 15607, 6282, 14317, 3574, 5616, 11702, 2544,
        14266, 10864, 5202, 2243, 12625, 3066, 3986, 5170,
        17477, 5151, 14849, 2806, 16928, 14067, 1839, 10626,
        5071, 13033, 8599, 13151, 5303, 16719, 8389, 5683,
        11762, 7311, 15096, 12292, 3747, 11066, 2170, 15726,
        5673, 33, 11550, 5214, 3050, 11910, 2642, 1614,
        16523, 4931, 11581, 4912, 2739, 8399, 8803, 18299,
        16957, 703, 6421, 476, 15261, 2360, 14948, 4220,
        494, 539, 4320, 11430, 662, 10200, 12431, 7929,
        5902, 2559, 10866, 17229, 6939, 10295, 8815, 4506,
        12758, 5338, 6567, 13919, 9634, 7825, 10666, 1339,
        7871, 14297, 8607, 10100, 17115, 353, 12952, 475,
        8899, 120, 5134, 527, 4388, 13146, 11283, 12572,
        10274, 3374, 1188, 16968, 2947, 2805, 4801, 798,
        11390, 10935, 11619, 13461, 3547, 13609, 7436, 11994,
        9960, 17136, 6875, 16270, 3571, 4456, 11228, 3594,
        8056, 5954, 971, 649, 5124, 8949, 16973, 13034,
        4083, 11955, 18392, 8724, 3979, 14752, 1960, 8258,
        15216, 3393, 7838, 1537, 15316, 11338, 5205, 3403,
        14924, 13373, 17001, 11572, 5447, 17100, 12708, 10582,
        14384, 7336, 5413, 16242, 1589, 18413, 11433, 15273,
        133, 2272, 2581, 8749, 4432, 5582, 18235, 15605,
        1999, 4905, 2481, 804, 4246, 7394, 7280, 6973,
        599, 4273, 2477, 11546, 16773, 15577, 14215, 9577,
        14461, 12532, 17579, 7725, 10946, 5152, 15199, 2964,
        13665, 11962, 2409, 9830, 8536, 7224, 3079, 16979,
        15928, 8349, 9736, 10399, 15897, 8651, 4838, 2816,
        7908, 16315, 14453, 15583, 3657, 13132, 6383, 10360,
        10538, 13289, 6034, 16733, 6062, 15271, 17713, 16528,
        751, 1603, 8060, 13645, 11305, 8790, 16622, 6345,
        15584, 10511, 10683, 1768, 4018, 11399, 8122, 13041,
        15440, 10130, 6364, 15302, 14049, 12978, 7782, 4461,
        6122, 1605, 8760, 13961, 12607, 14539, 1142, 11470,
        12992, 3653, 6673, 5751, 246, 2955, 2002, 6065,
        269, 5704, 5636, 16448, 8271, 9211, 16508, 17564,
        4184, 7998, 15917, 10240, 8592, 4300, 11927, 15812,
        12951, 12377, 195, 1668, 2206, 11213, 16754, 2086,
        11147, 9140, 10091, 6346, 14714, 5905, 2254, 11340,
        2752, 1137, 10857, 13749, 2867, 14882, 10594, 10365,
        13476, 12614, 9413, 2248, 9029, 1232, 7241, 10326,
        3882, 7967, 5067, 5342, 6844, 16572, 12238, 890,
        11454, 4960, 3298, 9494, 3185, 8811, 5539, 9663,
        17345, 9410, 12426, 12140, 6154, 7834, 13816, 2761,
        16106, 9588, 994, 3398, 11434, 3371, 138, 16494,
        7020, 4749, 3180, 13022, 13288, 1364, 16575, 12749,
        13049, 7260, 15679, 4234, 7412, 2714, 9817, 4853,
        3759, 15706, 4066, 11526, 12724, 4480, 1195, 7386,
        7074, 7196, 11712, 12555, 2614, 3076, 7486, 6750,
        16515, 7982, 10317, 7712, 16609, 13607, 6736, 11678,
        8130, 9990, 12663, 11615, 15074, 16074, 3835, 14371,
        4944, 13081, 6966, 2302, 18118, 7231, 5529, 18085,
        17351, 11730, 13374, 10040, 4968, 3928, 10758, 12335,
        5197, 6454, 10074, 5917, 17263, 8425, 17903, 3974,
        3881, 1436, 4909, 5692, 13186, 17223, 459, 11583,
        1231, 2873, 10168, 11542, 8590, 9671, 11611, 16512,
        1125, 11041, 11853, 11776, 17254, 4945, 16481, 7124,
        14235, 11166, 304, 13093, 6464, 4814, 7497, 4859,
        17756, 2433, 3632, 15754, 17078, 16768, 7106, 13425,
        18375, 8295, 9269, 1867, 17609, 892, 17272, 11905,
        5128, 16640, 17605, 11634, 12469, 16478, 16204, 4471,
        12437, 10249, 11148, 15671, 17786, 14033, 8372, 5254,
        10827, 2149, 14830, 7748, 16524, 11462, 11739, 4562,
        15821, 9986, 11263, 10983, 12470, 4576, 16362, 4121,
        2749, 18410, 10383, 14799, 3460, 16835, 12123, 5578,
        10944, 10523, 14883, 3664, 11830, 9027, 7407, 6925,
        1721, 14154, 13856, 5939, 16187, 4042, 13792, 11914,
        1890, 11913, 3692, 2088, 13503, 4621, 13679, 11231,
        7058, 13298, 9184, 18155, 11921, 13492, 3352, 11941
    };

    // Hawk-512 (logn = 9, n = 512)
    public static final short[] SIG_GAUSS_HI_HAWK_512 = {
            (short) 0x580B, (short) 0x35F9,
            (short) 0x1D34, (short) 0x0DD7,
            (short) 0x05B7, (short) 0x020C,
            (short) 0x00A2, (short) 0x002B,
            (short) 0x000A, (short) 0x0001
    };

    public static final short SG_MAX_HI_HAWK_512 = 10;

    public static final short[] SIG_GAUSS_LO_HI_HI_HAWK_512 = {
        (short)0x0C27, (short)0x3C68,
        (short)0x1C4F, (short)0x7B90,
        (short)0x5E63, (short)0x4EBE,
        (short)0x56AE, (short)0x4628,
        (short)0x061E, (short)0x7F76,
        (short)0x2BA5, (short)0x0668,
        (short)0x00CF, (short)0x0016,
        (short)0x0002, (short)0x0000,
        (short)0x0000, (short)0x0000,
        (short)0x0000, (short)0x0000,
        (short)0x0000, (short)0x0000,
        (short)0x0000, (short)0x0000,
        (short)0x0000, (short)0x0000
    };

    public static final short[] SIG_GAUSS_LO_HI_LO_HAWK_512 = {
        (short)0x920A, (short)0x9D92,
        (short)0xF17C, (short)0x8C81,
        (short)0x263B, (short)0xFD8F,
        (short)0xDFB0, (short)0xBC6B,
        (short)0x21D5, (short)0x9211,
        (short)0x68D9, (short)0xF461,
        (short)0x0F86, (short)0x70DB,
        (short)0x16A0, (short)0x2AB6,
        (short)0x02ED, (short)0x002C,
        (short)0x0002, (short)0x0000,
        (short)0x0000, (short)0x0000,
        (short)0x0000, (short)0x0000,
        (short)0x0000, (short)0x0000
    };

    public static final short[] SIG_GAUSS_LO_LO_HI_HAWK_512 = {
        (short)0x04F8, (short)0x1344,
        (short)0x204A, (short)0xFCE3,
        (short)0xE009, (short)0xF4F0,
        (short)0x876A, (short)0x2388,
        (short)0x88CC, (short)0xF07B,
        (short)0x2EEC, (short)0x693D,
        (short)0x87D3, (short)0x6596,
        (short)0xC344, (short)0xE11C,
        (short)0xF0B9, (short)0x253C,
        (short)0x3AF3, (short)0x18C1,
        (short)0x00EB, (short)0x0007,
        (short)0x0000, (short)0x0000,
        (short)0x0000, (short)0x0000
    };

    public static final short[] SIG_GAUSS_LO_LO_LO_HAWK_512 = {
        (short)0xF267, (short)0x9DC9,
        (short)0xA058, (short)0x524F,
        (short)0x8FFD, (short)0x7378,
        (short)0x3BD8, (short)0x7196,
        (short)0x61CC, (short)0x326F,
        (short)0x18E7, (short)0xFF8F,
        (short)0xB009, (short)0x4485,
        (short)0xEB45, (short)0x2552,
        (short)0x8A84, (short)0x7E81,
        (short)0xB2E7, (short)0x4ABF,
        (short)0xCC6A, (short)0x876E,
        (short)0x34CF, (short)0x013D,
        (short)0x0006, (short)0x0000
    };

    public static final short SG_MAX_LO_HAWK_512 = 26;

    // Constructor
    public Hawk() {
        logn = 9;
        n = (short) (1 << logn); // 2^logn = 512
        saltLen = 24;
        maxXnorm = 8317;
        random = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
    }

    // Helper methods
    public static short HAWK_SIG_SIZE(short logn) {
        return (short) (249 + 306 * (2 >> (10 - logn)) + 360 * (1 >> (10 - logn)));
    }
    /**
     * Hamming weight of a byte (number of 1 bits)
     */
    private static byte popcount8(byte x) {
        short v = (short) (x & 0xFF);
        v = (short) ((v & 0x55) + ((v >>> 1) & 0x55));
        v = (short) ((v & 0x33) + ((v >>> 2) & 0x33));
        v = (short) ((v & 0x0F) + ((v >>> 4) & 0x0F));
        return (byte) v;
    }

    /**
     * Regenerate f and g polynomials from seed using SHAKE256
     */
    public void regen_fg(byte[] f, short fOff, byte[] g, short gOff, byte[] seed) {
        for (byte j = 0; j < 4; j++) {
            SHAKE256JC shake = new SHAKE256JC();
            shake.update(seed, (short) 0, (short) 24);

            byte[] singleByte = new byte[1];
            singleByte[0] = j;
            shake.update(singleByte, (short) 0, (short) 1);
            byte[] qb = new byte[8];

            for (short u = 0; u < 1024; u += 32) {
                shake.doOutput(qb, (short) 0, (short) 8);

                for (short i = 0; i < 8; i++) {
                    byte coeff = (byte) (popcount8(qb[i]) - 4);

                    if (u < 512) {
                        f[(short) (fOff + u + (j << 3) + i)] = coeff;
                    } else {
                        g[(short) (gOff + (u - 512) + (j << 3) + i)] = coeff;
                    }
                }
            } 
        }
    }

    // Encode 32-bit integer as little-endian bytes
    public static void enc32le(byte[] dst, short dstOffset, short hi, short lo) {
        dst[dstOffset] = (byte)lo;
        dst[(short)(dstOffset + 1)] = (byte)(lo >>> 8);
        dst[(short)(dstOffset + 2)] = (byte)hi;
        dst[(short)(dstOffset + 3)] = (byte)(hi >>> 8);
    }

    // Decode 32-bit integer from little-endian bytes
    private static void dec32le(byte[] src, short off, short[] out, short outOff) {
        short lo = (short)((src[off] & 0xFF) | ((src[(short)(off + 1)] & 0xFF) << 8));
        short hi = (short)((src[(short)(off + 2)] & 0xFF) | ((src[(short)(off + 3)] & 0xFF) << 8));
        out[outOff] = hi;
        out[(short)(outOff + 1)] = lo;
    }

    // Decode 16-bit integer from little-endian bytes
    private static short dec16le(byte[] src, short off) {
        return (short)((src[off] & 0xFF) | ((src[(short)(off + 1)] & 0xFF) << 8));
    }

    /*
     * Returns 1 iff a < b when interpreted as unsigned ints.
     */
    private static short uLessThan(short aHi, short aLo, short bHi, short bLo)
    {
        if (aHi != bHi) {
            return (short)(((aHi ^ (short)0x8000) < (bHi ^ (short)0x8000)) ? 1 : 0);
        }
        return (short)(((aLo ^ (short)0x8000) < (bLo ^ (short)0x8000)) ? 1 : 0);
    }

    /*
     * Extract the lowest bit of each coefficient
     */
    private static void extract_lowbit(short logn, byte[] dst, byte[] src) {
        short n = (short) (1 << logn);
        for (short i = 0; i < n; i += 8) {
            byte val = 0;
            for (short j = 0; j < 8; j++) {
                if ((src[(short)(i + j)] & 1) != 0) {
                     val |= (byte)(1 << j);
                }
            }
            dst[(short) (i >> 3)] = val;
        }
    }

    static short tbmask(short x) {
        return (short) (x >> 15);
    }

    // Constants for sizes
    public static final short SIZE_64 = 64;
    public static final short SIZE_128 = 128;
    public static final short SIZE_256 = 256;
    public static final short SIZE_512 = 512;

    // Precomputed byte lengths
    private static final short BYTES_64 = SIZE_64 / 8;
    private static final short BYTES_128 = SIZE_128 / 8;

    /**
    * XOR of two 64-bit binary polynomials represented as byte arrays.
    */
    public static void bpXor64(byte[] d, short dOffset, byte[] a, short aOffset, byte[] b, short bOffset) {
        short[] ta = new short[2];
        short[] tb = new short[2];

        // low 32 bits
        dec32le(a, aOffset, ta, (short)0);
        dec32le(b, bOffset, tb, (short)0);

        short loHi = (short)(ta[0] ^ tb[0]);
        short loLo = (short)(ta[1] ^ tb[1]);

        // high 32 bits
        dec32le(a, (short)(aOffset + 4), ta, (short)0);
        dec32le(b, (short)(bOffset + 4), tb, (short)0);

        short hiHi = (short)(ta[0] ^ tb[0]);
        short hiLo = (short)(ta[1] ^ tb[1]);

        enc32le(d, dOffset, loHi, loLo);
        enc32le(d, (short)(dOffset + 4), hiHi, hiLo);
    }

     /**
    * Computes the 64-bit product of two 32-bit integers without using Java long arithmetic.
    */
    public static void mul64( short aHi, short aLo, short bHi, short bLo, short[] out, short off)
    {
        U32 p00 = new U32();
        U32 p01 = new U32();
        U32 p10 = new U32();
        U32 p11 = new U32();

        mul16(aLo, bLo, p00);
        mul16(aLo, bHi, p01);
        mul16(aHi, bLo, p10);
        mul16(aHi, bHi, p11);

        short r0 = p00.lo;

        short t1 = (short)(p00.hi + p01.lo);
        short carry1 = uLessThan((short)0, t1, (short)0, p00.hi);

        short old = t1;
        t1 = (short)(t1 + p10.lo);

        if (uLessThan((short)0, t1, (short)0, old) != 0) {
            carry1++;
        }

        short r1 = t1;
        short t2 = (short)(p01.hi + p10.hi);
        short carry2 = uLessThan((short)0, t2, (short)0, p01.hi);

        old = t2;
        t2 = (short)(t2 + p11.lo);
        if (uLessThan((short)0, t2, (short)0, old) != 0) {
            carry2++;
        }

        old = t2;
        t2 = (short)(t2 + carry1);
        if (uLessThan((short)0, t2, (short)0, old) != 0) {
            carry2++;
        }

        short r2 = t2;
        short r3 = (short)(p11.hi + carry2);
        out[off] = r0;
        out[(short)(off + 1)] = r1;
        out[(short)(off + 2)] = r2;
        out[(short)(off + 3)] = r3;
    }

    /**
     * Multiplies two 32-bit binary polynomials over GF(2).
     */
    public static void bpMul32(short xHi, short xLo, short yHi, short yLo, short[] out, short off) {
        U32 x = new U32(xHi, xLo);

        U32 x0 = new U32();
        U32 x1 = new U32();
        U32 x2 = new U32();
        U32 x3 = new U32();

        U32.andMask(x, U32.MASK1, x0);
        U32.andMask(x, U32.MASK2, x1);
        U32.andMask(x, U32.MASK4, x2);
        U32.andMask(x, U32.MASK8, x3);

        U32 y = new U32(yHi, yLo);

        U32 y0 = new U32();
        U32 y1 = new U32();
        U32 y2 = new U32();
        U32 y3 = new U32();

        U32.andMask(y, U32.MASK1, y0);
        U32.andMask(y, U32.MASK2, y1);
        U32.andMask(y, U32.MASK4, y2);
        U32.andMask(y, U32.MASK8, y3);

        U32 z0hi = new U32();
        U32 z0lo = new U32();

        short[] mul = new short[4];
        U32 hiPart = new U32();
        U32 loPart = new U32();
        mul64(
            x0.hi, x0.lo,
            y0.hi, y0.lo,
            mul, (short)0);

        hiPart.hi = mul[3];
        hiPart.lo = mul[2];

        loPart.hi = mul[1];
        loPart.lo = mul[0];
        U32.xor(z0hi, hiPart, z0hi);
        U32.xor(z0lo, loPart, z0lo);

        mul64( x1.hi, x1.lo, y3.hi, y3.lo, mul, (short)0);

        hiPart.hi = mul[3];
        hiPart.lo = mul[2];

        loPart.hi = mul[1];
        loPart.lo = mul[0];
        U32.xor(z0hi, hiPart, z0hi);
        U32.xor(z0lo, loPart, z0lo);

        mul64( x2.hi, x2.lo, y2.hi, y2.lo, mul, (short)0);
        hiPart.hi = mul[3];
        hiPart.lo = mul[2];

        loPart.hi = mul[1];
        loPart.lo = mul[0];
        U32.xor(z0hi, hiPart, z0hi);
        U32.xor(z0lo, loPart, z0lo);

        mul64(x3.hi, x3.lo, y1.hi, y1.lo, mul, (short)0);
        hiPart.hi = mul[3];
        hiPart.lo = mul[2];

        loPart.hi = mul[1];
        loPart.lo = mul[0];
        U32.xor(z0hi, hiPart, z0hi);
        U32.xor(z0lo, loPart, z0lo);

        U32 z1hi = new U32();
        U32 z1lo = new U32();

        mul64(x0.hi, x0.lo, y1.hi, y1.lo, mul, (short)0);
        hiPart.hi = mul[3];
        hiPart.lo = mul[2];

        loPart.hi = mul[1];
        loPart.lo = mul[0];
        U32.xor(z1hi, hiPart, z1hi);
        U32.xor(z1lo, loPart, z1lo);

        mul64(x1.hi, x1.lo, y0.hi, y0.lo, mul, (short)0);
        hiPart.hi = mul[3];
        hiPart.lo = mul[2];

        loPart.hi = mul[1];
        loPart.lo = mul[0];
        U32.xor(z1hi, hiPart, z1hi);
        U32.xor(z1lo, loPart, z1lo);

        mul64(x2.hi, x2.lo, y3.hi, y3.lo, mul, (short)0);
        hiPart.hi = mul[3];
        hiPart.lo = mul[2];

        loPart.hi = mul[1];
        loPart.lo = mul[0];
        U32.xor(z1hi, hiPart, z1hi);
        U32.xor(z1lo, loPart, z1lo);

        mul64(x3.hi, x3.lo, y2.hi, y2.lo, mul, (short)0);
        hiPart.hi = mul[3];
        hiPart.lo = mul[2];

        loPart.hi = mul[1];
        loPart.lo = mul[0];
        U32.xor(z1hi, hiPart, z1hi);
        U32.xor(z1lo, loPart, z1lo);

        U32 z2hi = new U32();
        U32 z2lo = new U32();

        mul64(x0.hi, x0.lo, y2.hi, y2.lo, mul, (short)0);
        hiPart.hi = mul[3];
        hiPart.lo = mul[2];

        loPart.hi = mul[1];
        loPart.lo = mul[0];
        U32.xor(z2hi, hiPart, z2hi);
        U32.xor(z2lo, loPart, z2lo);

        mul64(x1.hi, x1.lo, y1.hi, y1.lo, mul, (short)0);
        hiPart.hi = mul[3];
        hiPart.lo = mul[2];

        loPart.hi = mul[1];
        loPart.lo = mul[0];
        U32.xor(z2hi, hiPart, z2hi);
        U32.xor(z2lo, loPart, z2lo);

        mul64(x2.hi, x2.lo, y0.hi, y0.lo, mul, (short)0);
        hiPart.hi = mul[3];
        hiPart.lo = mul[2];

        loPart.hi = mul[1];
        loPart.lo = mul[0];
        U32.xor(z2hi, hiPart, z2hi);
        U32.xor(z2lo, loPart, z2lo);

        mul64(x3.hi, x3.lo, y3.hi, y3.lo, mul, (short)0);
        hiPart.hi = mul[3];
        hiPart.lo = mul[2];

        loPart.hi = mul[1];
        loPart.lo = mul[0];
        U32.xor(z2hi, hiPart, z2hi);
        U32.xor(z2lo, loPart, z2lo);

        U32 z3hi = new U32();
        U32 z3lo = new U32();

        mul64(x0.hi, x0.lo, y3.hi, y3.lo, mul, (short)0);
        hiPart.hi = mul[3];
        hiPart.lo = mul[2];

        loPart.hi = mul[1];
        loPart.lo = mul[0];
        U32.xor(z3hi, hiPart, z3hi);
        U32.xor(z3lo, loPart, z3lo);

        mul64(x1.hi, x1.lo, y2.hi, y2.lo, mul, (short)0);
        hiPart.hi = mul[3];
        hiPart.lo = mul[2];

        loPart.hi = mul[1];
        loPart.lo = mul[0];
        U32.xor(z3hi, hiPart, z3hi);
        U32.xor(z3lo, loPart, z3lo);

        mul64(x2.hi, x2.lo, y1.hi, y1.lo, mul, (short)0);
        hiPart.hi = mul[3];
        hiPart.lo = mul[2];

        loPart.hi = mul[1];
        loPart.lo = mul[0];
        U32.xor(z3hi, hiPart, z3hi);
        U32.xor(z3lo, loPart, z3lo);

        mul64(x3.hi, x3.lo, y0.hi, y0.lo, mul, (short)0);
        hiPart.hi = mul[3];
        hiPart.lo = mul[2];

        loPart.hi = mul[1];
        loPart.lo = mul[0];
        U32.xor(z3hi, hiPart, z3hi);
        U32.xor(z3lo, loPart, z3lo);

        U32.andMask(z0hi, U32.MASK1, z0hi);
        U32.andMask(z0lo, U32.MASK1, z0lo);

        U32.andMask(z1hi, U32.MASK2, z1hi);
        U32.andMask(z1lo, U32.MASK2, z1lo);

        U32.andMask(z2hi, U32.MASK4, z2hi);
        U32.andMask(z2lo, U32.MASK4, z2lo);

        U32.andMask(z3hi, U32.MASK8, z3hi);
        U32.andMask(z3lo, U32.MASK8, z3lo);

        U32 hii = new U32();
        U32 loo = new U32();

        U32.or(z0hi, z1hi, hii);
        U32.or(hii, z2hi, hii);
        U32.or(hii, z3hi, hii);

        U32.or(z0lo, z1lo, loo);
        U32.or(loo, z2lo, loo);
        U32.or(loo, z3lo, loo);

        out[off] = hii.lo;
        out[(short)(off + 1)] = hii.hi;

        out[(short)(off + 2)] = loo.lo;
        out[(short)(off + 3)] = loo.hi;
    }

    /**
     * Multiply-and-accumulate operation for 64-bit binary polynomials.
     * Uses a Karatsuba-style decomposition to avoid 64-bit arithmetic.
     */
    public static void bpMuladd64(byte[] d, short dOffset, byte[] a, short aOffset, byte[] b, short bOffset, byte[] tmp, short tmpOffset)
    {
        short[] t = new short[8];

        // a0
        dec32le(a, aOffset, t, (short)0);
        U32 a0 = new U32(t[0], t[1]);

        // a1
        dec32le(a, (short)(aOffset + 4), t, (short)0);
        U32 a1 = new U32(t[0], t[1]);

        // b0
        dec32le(b, bOffset, t, (short)0);
        U32 b0 = new U32(t[0], t[1]);

        // b1
        dec32le(b, (short)(bOffset + 4), t, (short)0);
        U32 b1 = new U32(t[0], t[1]);

        U32 c0 = new U32();
        U32 c1 = new U32();
        U32 c2 = new U32();
        U32 c3 = new U32();
        U32 c4 = new U32();
        U32 c5 = new U32();

        short[] mul32 = new short[4];

        bpMul32(a0.hi, a0.lo, b0.hi, b0.lo, mul32, (short)0);

        U32.set(c0, mul32[1], mul32[0]);
        U32.set(c1, mul32[3], mul32[2]);

        bpMul32(a1.hi, a1.lo, b1.hi, b1.lo, mul32, (short)0);

        U32.set(c2, mul32[1], mul32[0]);
        U32.set(c3, mul32[3], mul32[2]);

        U32 ax = new U32();
        U32 bx = new U32();

        U32.xor(a0, a1, ax);
        U32.xor(b0, b1, bx);

        bpMul32(ax.hi, ax.lo, bx.hi, bx.lo, mul32, (short)0);

        U32.set(c4, mul32[1], mul32[0]);
        U32.set(c5, mul32[3], mul32[2]);

        U32.xor(c4, c0, c4);
        U32.xor(c5, c1, c5);

        U32.xor(c4, c2, c4);
        U32.xor(c5, c3, c5);

        dec32le(d, dOffset, t, (short)0);
        U32 d0lo = new U32(t[0], t[1]);
        dec32le(d, (short)(dOffset + 4), t, (short)0);
        U32 d0hi = new U32(t[0], t[1]);
        dec32le(d, (short)(dOffset + 8), t, (short)0);
        U32 d1lo = new U32(t[0], t[1]);
        dec32le(d, (short)(dOffset + 12), t, (short)0);
        U32 d1hi = new U32(t[0], t[1]);

        U32.xor(d0hi, c0, d0hi);
        U32.xor(d0hi, c5, d0hi);
        U32.xor(d0lo, c1, d0lo);
        U32.xor(d1hi, c2, d1hi);
        U32.xor(d1lo, c3, d1lo);
        U32.xor(d1lo, c4, d1lo);

        enc32le(d, dOffset, d0lo.hi, d0lo.lo);
        enc32le(d, (short)(dOffset + 4), d0hi.hi, d0hi.lo);
        enc32le(d, (short)(dOffset + 8), d1lo.hi, d1lo.lo);
        enc32le(d, (short)(dOffset + 12), d1hi.hi, d1hi.lo);
    }

    /** 
     * XOR of two 512-bit binary polynomials.
     */
    private static void bpXor512(byte[] d, short dOffset, byte[] a, short aOffset, byte[] b, short bOffset) {
        for (short u = 0; u < 64; u++) {
            d[(short) (dOffset + u)] = (byte) (a[(short)(aOffset + u)] ^ b[(short) (bOffset + u)]);
        }
    }

    /** 
     * XOR of two 128-bit binary polynomials.
     */
    public static void bpXor128(byte[] d, short dOffset, byte[] a, short aOffset, byte[] b, short bOffset) {
        // Process as two 64-bit chunks
        bpXor64(d, dOffset, a, aOffset, b, bOffset);
        bpXor64(d, (short) (dOffset + 8), a, (short) (aOffset + 8), b,(short) (bOffset + 8));
    }

    /**
     * Multiply-and-accumulate operation for 128-bit binary polynomials.
     */
    public static void bpMuladd128(byte[] d, short dOffset,  byte[] a, short aOffset, byte[] b, short bOffset, byte[] tmp, short tmpOffset) {
        // Use optimized implementation for 128-bit polynomials
        short t1Offset = tmpOffset;
        short t2Offset = (short) (t1Offset + BYTES_128);

        // Karatsuba algorithm for 128-bit polynomials (split into 64-bit halves)
        bpXor64(tmp, t2Offset, a, aOffset, a, (short) (aOffset + BYTES_64)); // a0 + a1
        bpXor64(tmp, (short) (t2Offset + BYTES_64), b, bOffset, b, (short) (bOffset + BYTES_64)); // b0 + b1

        // t1 = (a0+a1)*(b0+b1) + d0 + d1
        bpXor128(tmp, t1Offset, d, dOffset, d, (short) (dOffset + BYTES_128));
        bpMuladd64(tmp, t1Offset, tmp, t2Offset, tmp, (short) (t2Offset + BYTES_64), tmp, (short) (t2Offset + BYTES_128));

        // d0 += a0*b0
        bpMuladd64(d, dOffset, a, aOffset, b, bOffset, tmp, t2Offset);

        // d1 += a1*b1
        bpMuladd64(d, (short) (dOffset + BYTES_128), a, (short) (aOffset + BYTES_64), b, (short) (bOffset + BYTES_64), tmp, t2Offset);

        // t1 = t1 + d0 + d1 = a0*b1 + a1*b0
        bpXor128(tmp, t1Offset, tmp, t1Offset, d, dOffset);
        bpXor128(tmp, t1Offset, tmp, t1Offset, d, (short) (dOffset + BYTES_128));

        // d += (x^64)*t1: d[8:24] ⊕= t1[0:16]
        bpXor128(d, (short) (dOffset + BYTES_64), d, (short) (dOffset + BYTES_64), tmp, t1Offset);
    }

    /** 
     * XOR of two 256-bit binary polynomials.
     */
    private static void bpXor256(byte[] d, short dOffset, byte[] a, short aOffset, byte[] b, short bOffset) {
        for (short u = 0; u < 32; u++) {
            d[(short) (dOffset + u)] = (byte) (a[(short) (aOffset + u)] ^ b[(short) (bOffset + u)]);
        }
    }

    /**
     * Binary polynomial multiplication and accumulation for 256-bit polynomials.
     * Uses Karatsuba algorithm with 128-bit halves.
     */
    public static void bpMuladd256(byte[] d, short dOffset, byte[] a, short aOffset, byte[] b, short bOffset, byte[] tmp, short tmpOffset) {
        final short byteLen = 32;
        final short halfByteLen = 16;

        // Temporary buffers within the provided tmp array
        short t1Offset = tmpOffset;
        short t2Offset = (short) (t1Offset + byteLen);
        short t3Offset = (short) (t2Offset + byteLen);

        // t1 <- (a0 + a1)*(b0 + b1) + d0 + d1
        bpXor128(tmp, t2Offset, a, aOffset, a, (short) (aOffset + halfByteLen)); // a0 + a1
        bpXor128(tmp, (short) (t2Offset + halfByteLen), b, bOffset, b, (short) (bOffset + halfByteLen)); // b0 + b1
        bpXor256(tmp, t1Offset, d, dOffset, d, (short) (dOffset + byteLen)); // d0 + d1
        bpMuladd128(tmp, t1Offset, tmp, t2Offset, tmp, (short) (t2Offset + halfByteLen), tmp, t3Offset);

        // d0 <- d0 + a0*b0
        bpMuladd128(d, dOffset, a, aOffset, b, bOffset, tmp, t3Offset);

        // d1 <- d1 + a1*b1
        bpMuladd128(d, (short) (dOffset + byteLen), a, (short) (aOffset + halfByteLen), b, (short) (bOffset + halfByteLen), tmp, t3Offset);

        // t1 <- t1 + d0 + d1 = a0*b1 + a1*b0
        bpXor256(tmp, t1Offset, tmp, t1Offset, d, dOffset);
        bpXor256(tmp, t1Offset, tmp, t1Offset, d, (short) (dOffset + byteLen));

        // d <- d + (x^{n/2})*t1: d[16:48] ⊕= t1[0:32]
        bpXor256(d, (short) (dOffset + halfByteLen), d, (short) (dOffset + halfByteLen), tmp, t1Offset);
    }

    /**
     * Generic XOR for any size.
     */
    private static void bpXor(short bitSize, byte[] d, short dOffset, byte[] a, short aOffset, byte[] b, short bOffset)
    {
        short byteSize = (short)(bitSize >> 3);
        for (short u = 0; u < byteSize; u++) {
            d[(short)(dOffset + u)] = (byte)(a[(short)(aOffset + u)] ^ b[(short)(bOffset + u)]);
        }
    }

    /**
     * Generic binary polynomial multiplication using Karatsuba algorithm
     */
    private static void bpMulmod(short n, short hn, byte[] d, short dOffset, byte[] a, short aOffset, byte[] b, short bOffset, byte[] tmp, short tmpOffset)
    {
        short byteLen = (short)(n / 8);
        short halfByteLen = (short)(hn / 8);

        short t1Offset = tmpOffset;
        short t2Offset = (short)(t1Offset + byteLen);

        // t1 <- (a0 + a1)*(b0 + b1)
        bpXor(hn, d, dOffset, a, aOffset, a, (short)(aOffset + halfByteLen));
        bpXor(hn, d, (short)(dOffset + halfByteLen), b, bOffset, b, (short)(bOffset + halfByteLen));
        bpXor(n, tmp, t1Offset, d, dOffset, d, (short)(dOffset + halfByteLen));
        Util.arrayFillNonAtomic(tmp, t1Offset, byteLen, (byte)0);
        bpMuladd256( tmp, t1Offset, d, dOffset, d, (short)(dOffset + halfByteLen), tmp, t2Offset);

        // d <- a0*b0 + a1*b1
        Util.arrayFillNonAtomic(d, dOffset, byteLen, (byte)0);
        bpMuladd256(d, dOffset, a, aOffset, b, bOffset, tmp, t2Offset);
        bpMuladd256(d, dOffset, a, (short)(aOffset + halfByteLen), b, (short)(bOffset + halfByteLen), tmp, t2Offset);

        // t1 <- t1 + d = a0*b1 + a1*b0
        bpXor(n, tmp, t1Offset, tmp, t1Offset, d, dOffset);

        // d <- d + rotate_{n/2}(t1)
        bpXor(hn, d, dOffset, d, dOffset, tmp, (short)(t1Offset + halfByteLen));
        bpXor(hn, d, (short)(dOffset + halfByteLen), d, (short)(dOffset + halfByteLen), tmp, t1Offset);
    }

    /**
     * Basis multiplication modulo 2
     */
    public static void basisM2Mul(
            short logn,
            byte[] t0, short t0Offset,
            byte[] t1, short t1Offset,
            byte[] h0, short h0Offset,
            byte[] h1, short h1Offset,
            byte[] f2, short f2Offset,
            byte[] g2, short g2Offset,
            byte[] F2, short F2Offset,
            byte[] G2, short G2Offset,
            byte[] tmp, short tmpOffset)
    {
        short n = (short)(1 << logn);
        short byteLen = (short)(n >> 3);

        short w1Offset = tmpOffset;
        short w2Offset = (short)(w1Offset + byteLen);

        bpMulmod((short)512, (short)256, t0, t0Offset, h0, h0Offset, f2, f2Offset, tmp, w2Offset);
        bpMulmod((short)512, (short)256, tmp, w1Offset, h1, h1Offset, F2, F2Offset, tmp, w2Offset);
        bpXor512(t0, t0Offset, t0, t0Offset, tmp, w1Offset);
        bpMulmod((short)512, (short)256, t1, t1Offset, h0, h0Offset, g2, g2Offset, tmp, w2Offset);
        bpMulmod((short)512, (short)256, tmp, w1Offset, h1, h1Offset, G2, G2Offset, tmp, w2Offset);
        bpXor512(t1, t1Offset, t1, t1Offset, tmp, w1Offset);
    }

    /**
     * Convert a signed byte to a mod q value in the range [0, q-1]
     * This is the equivalent of Zq(set_small)
     */
    public short mq18433SetSmall(byte x) {
        // C formula: uint32_t y = (uint32_t)-x; y += Q & (y >> 16); return Q - y;
        // This returns values in [1..Q] where Q represents 0 mod Q.
        int xInt = (int) x; // sign-extend byte to int
        int y = -xInt; // same bit pattern as C's (uint32_t)-x
        y += Q & (y >>> 16); // unsigned right shift to detect negative (large unsigned) values
        return (short) (Q - y);
    }

    /**
     * Convert a small polynomial (signed 8-bit coefficients) to mod q
     * representation.
     * This is the equivalent of Zq(poly_set_small)
     */
    public void mq18433PolySetSmall(short logn, short[] d, short dOffset, byte[] a, short aOffset) {
        short n = (short) (1 << logn);
        for (short u = 0; u < n; u++) {
            d[(short) (dOffset + u)] = mq18433SetSmall(a[(short) (aOffset + u)]);
        }
    }

    /**
     * Modular subtraction: (x - y) mod Q,
     * result in [1..Q] where Q represents 0 mod Q.
     */
    public short mq18433Sub(short x, short y)
    {
        short d = (short)(y - x);
        short mask = (short)(d >> 15);
        d = (short)(d + (Q & mask));
        return (short)(Q - d);
    }

    /**
     * Modular addition: (x + y) mod Q,
     * result in [1..Q] where Q represents 0 mod Q.
     */
    public short mq18433Add(short x, short y)
    {
        short s = (short)(x + y);
        short d = (short)(s - Q);
        short mask = (short)(d >> 15);
        return (short)(d + (Q & mask));
    }

     static void mul16(short a, short b, U32 out)
    {
        short al = (short)(a & 0xFF);
        short ah = (short) ((short)(a >>> 8) & 0xFF);

        short bl = (short)(b & 0xFF);
        short bh = (short) ((short)(b >>> 8) & 0xFF);

        int p0 = al * bl;
        int p1 = al * bh;
        int p2 = ah * bl;
        int p3 = ah * bh;

        int middle = (p0 >>> 8) + (p1 & 0xFF) + (p2 & 0xFF);
        out.lo = (short)((p0 & 0xFF) | ((middle & 0xFF) << 8));
        out.hi = (short)(p3 + (p1 >>> 8) + (p2 >>> 8) + (middle >>> 8));
    }

    /**
     * Montgomery reduction.
     */
    public short mq18433MontyRed(short xHi, short xLo)
    {
        U32 pLL = new U32();
        U32 pLH = new U32();
        U32 pHL = new U32();
        U32 step2 = new U32();

        mul16(xLo, (short)18431, pLL);
        mul16(xLo, (short)60352, pLH);
        mul16(xHi, (short)18431, pHL);

        short word16 = (short)(pLL.hi + pLH.lo + pHL.lo);
        mul16(word16, Q, step2);
        short result = (short)(step2.hi + 1);
        if (xHi == 0 && xLo == 0) {
            return 0;
        }

        return result;
    }

    /**
     * Montgomery multiplication: returns (x * y) mod Q in Montgomery form
     */
    public short mq18433MontyMul(short x, short y)
    {
        U32 product = new U32();
        mul16(x, y, product);
        return mq18433MontyRed(product.hi, product.lo);
    }

    /**
     * Convert a number to Montgomery form
     */
    public short mq18433ToMonty(short x)
    {
        U32 product = new U32();
        mul16(x, R2, product);
        return mq18433MontyRed(product.hi,product.lo);
    }

     /**
     * Compute half: x/2 mod Q. Constant-time: x is a secret-derived INTT
     * butterfly intermediate (each butterfly calls this O(n log n) per signing
     * INTT), so the "is x odd" branch must not be data-dependent. Same pattern
     * as HawkEngine.mpHalf — fold the conditional `+ Q` (only applied when x is
     * odd, to keep the result an integer) into a branchless mask.
     */
    public short mq18433Half(short x)
    {
        if ((x & 1) != 0) {
            x = (short)(x + Q);
        }
        return (short)((x >>> 1) & 0x7FFF);
    }

    /**
     * Number Theoretic Transform (NTT) for modulus 18433
     */
    public void mq18433NTT(short logn, short[] a, short aOffset) {
        if (logn == 0) {
            return;
        }

        int t = 1 << logn;
        for (short lm = 0; lm < logn; lm++) {
            int m = 1 << lm;
            int ht = t >> 1;
            int v0 = 0;

            for (short u = 0; u < m; u++) {
                short s = (short)(GM[(short) (u + m)]);

                for (short v = 0; v < ht; v++) {
                    int k1 = aOffset + v0 + v;
                    int k2 = k1 + ht;

                    short x1 = (short)(a[(short) k1]);
                    short x2 = (short)(a[(short) k2]);

                    short x2Monty = mq18433MontyMul(x2, s);

                    a[k1] = mq18433Add(x1, x2Monty);
                    a[k2] = mq18433Sub(x1, x2Monty);
                }
                v0 += t;
            }
            t = ht;
        }
    }

     /**
     * Inverse NTT matching C mq18433_iNTT exactly.
     * 1/n normalization is embedded in the iGM twiddle factors.
     */
    public void mq18433INTT(short logn, short[] a, short aOffset)
    {
        if (logn == 0)
        {
            return;
        }

        int t = 1;

        for (short lm = 0; lm < logn; lm++)
        {
            int hm = 1 << (logn - 1 - lm);
            int dt = t << 1;
            int v0 = 0;

            for (short u = 0; u < hm; u++)
            {
                short s = (short)(iGM[(short) (u + hm)]);

                for (short v = 0; v < t; v++)
                {
                    int k1 = aOffset + v0 + v;
                    int k2 = k1 + t;

                    short x1 = (short)(a[(short) k1]);
                    short x2 = (short)(a[(short) k2]);

                    a[k1] = mq18433Half(mq18433Add(x1, x2));

                    a[k2] = mq18433MontyMul(s, mq18433Sub(x1, x2));
                }

                v0 += dt;
            }

            t = dt;
        }
    }

    /**
     * Convert a coefficient from the modular range [0, Q-1] to the centered signed range approximately [-Q/2, Q/2].
     */
    public static short mq18433Snorm(short x)
    {
        if (x > (Q >> 1)) {
            return (short)(x - Q);
        }

        return x;
    }

    /**
     * Apply signed normalization to polynomial coefficients
     */
    public static void mq18433PolySnorm(short logn, short[] d, short dOffset) {
        short n = (short) (1 << logn);
        for (short u = 0; u < n; u++) {
            short k = (short) (dOffset + u);
            d[k] = mq18433Snorm(d[k]);
        }
    }

    /**
     * Returned value:
     * 1 first non-zero coefficient of s is positive
     * -1 first non-zero coefficient of s is negative
     * 0 s is entirely zero
     */
    public static short polySymBreak(short logn, short[] s, short sOffset)
    {
        int n = 1 << logn;
        short r = 0;
        short c = (short)0xFFFF;

        for (short u = 0; u < n; u++) {

            short x = s[(short) (sOffset + u)];
            short nz = (short)(c & tbmask((short)(x | -x)));
            c = (short)(c & ~nz);
            r = (short)(r | (nz & (short)(tbmask(x) | 1)));
        }

        return r;
    }

    private static void dec64le(byte[] src, short off, U64 out)
    {
        out.w0 = (short)((src[off] & 0xFF) | ((src[(short)(off + 1)] & 0xFF) << 8));
        out.w1 = (short)((src[(short)(off + 2)] & 0xFF) | ((src[(short)(off + 3)] & 0xFF) << 8));
        out.w2 = (short)((src[(short)(off + 4)] & 0xFF) | ((src[(short)(off + 5)] & 0xFF) << 8));
        out.w3 = (short)((src[(short)(off + 6)] & 0xFF) | ((src[(short)(off + 7)] & 0xFF) << 8));
    }

    /**
     * Generate x with the right Gaussian, for the specified parity bits.
     *
     * Returned value is the squared norm of x.
     */
    public short sigGauss(short logn, SHAKE256JC shake, byte[] x, short xOffset, byte[] t, short tOffset) {
        short[] tabLoHiHi, tabLoHiLo, tabLoLoHi, tabLoLoLo, tabHi;
        short hiLen, loLen;

        tabHi = SIG_GAUSS_HI_HAWK_512;
        tabLoHiHi = SIG_GAUSS_LO_HI_HI_HAWK_512;
        tabLoHiLo = SIG_GAUSS_LO_HI_LO_HAWK_512;
        tabLoLoHi = SIG_GAUSS_LO_LO_HI_HAWK_512;
        tabLoLoLo = SIG_GAUSS_LO_LO_LO_HAWK_512;
        hiLen = SG_MAX_HI_HAWK_512;
        loLen = SG_MAX_LO_HAWK_512;

        int n = 1 << logn;
        byte[] seed = new byte[41];
        byte[] tmp = new byte[40];
        random.generateData(tmp, (short) 0, (short) 40);
        Util.arrayCopy(tmp, (short) 0, seed,(short) 0, (short) tmp.length);

        int sn = 0;

        for (short j = 0; j < 4; j++) {
            SHAKE256JC sc = new SHAKE256JC(shake);

            seed[40] = (byte)j;
            sc.update(seed, (short) 0, (short) 41);
            byte[] buffer = new byte[40];

            short limit = (short)(n << 1);

            for (short u = 0; u < limit; u += 16) {
                sc.doOutput(buffer, (short) 0, (short) 40);
                for (short k = 0; k < 4; k++) {
                    int v = u + (j << 2) + k;
                    U64 lo = new U64();
                    dec64le(buffer,(short)(k << 3), lo);
                    short hi = dec16le(buffer,(short)(32 + (k << 1)));
                    short neg = (short)-U64.msb(lo);
                    U64.clearMsb(lo);
                    hi = (short)(hi & 0x7FFF);
                    short pbit =(short)((t[(short)(tOffset + (v >>> 3))] >>> (v & 7)) & 1);

                    short pOddw = (short)-pbit;
                    short r = 0;
                    U64 tlo0 = new U64();
                    U64 tlo1 = new U64();
                    U64 tlo  = new U64();

                    /*
                     * Main comparison loop.
                     */
                    for (short i = 0; i < hiLen; i += 2) {
                        short mask = pOddw;
                        short thi = (short)(tabHi[i] ^ (mask & (tabHi[i] ^ tabHi[(short)(i + 1)]) ));
                        U64.getU64(tabLoHiHi, tabLoHiLo, tabLoLoHi, tabLoLoLo, i, tlo0);
                        U64.getU64( tabLoHiHi, tabLoHiLo, tabLoLoHi, tabLoLoLo, (short)(i + 1), tlo1);
                        U64.select(tlo0, tlo1, mask, tlo);
                        short cc = U64.ult(lo, tlo);
                        short diffHi16 = (short)(hi - thi - cc);
                        r += (short)((diffHi16 < 0) ? 1 : 0);
                    }

                    /*
                     * Remaining entries.
                     */
                    short hinz = (short)((hi == 0) ? 1 : 0);
                    for (short i = hiLen; i < loLen; i += 2)
                    {
                        short mask = pOddw;
                        U64.getU64(tabLoHiHi, tabLoHiLo, tabLoLoHi, tabLoLoLo, i, tlo0);
                        U64.getU64(tabLoHiHi, tabLoHiLo, tabLoLoHi, tabLoLoLo, (short)(i + 1), tlo1);
                        U64.select(tlo0, tlo1, mask, tlo);
                        short cc = U64.ult(lo, tlo);
                        r += (short)(hinz & cc);
                    }
                    r = (short)((r << 1) - pOddw);
                    r = (short)((r ^ neg) - neg);
                    x[(short)(xOffset + v)] = (byte)r;
                    sn += r * r;
                }
            }
        }
        return (short) sn;
    }

    /**
     * Encode the signature, with output length exactly sigLen bytes.
     * Padding is applied if necessary. Returned value is 1 on success, 0
     * on error; an error is reported if the signature does not fit in the
     * provided buffer.
     */
    public static boolean encodeSig(short logn, byte[] sig, short sigOffset, short sigLen, byte[] salt, short saltOffset, short saltLen, short[] s1, short s1Offset) {
        short n = (short) (1 << logn);
        byte low = (byte) ((logn == 10) ? 6 : 5);

        short bufOffset = sigOffset;
        short remainingLen = (short) sigLen;

        short minSize = (short) (saltLen + (((short) (low + 2)) << (logn - 3)));

        if (remainingLen < minSize) {
            return false;
        }

        // 1. Copy salt
        Util.arrayCopyNonAtomic(salt, saltOffset, sig, bufOffset, saltLen);

        bufOffset += saltLen;
        remainingLen -= saltLen;

        // 2. Sign bits
        short u;
        short v;

        for (u = 0; u < n; u += 8) {
            byte x = 0;
            for (v = 0; v < 8; v++) {
                short coeff = s1[(short) (s1Offset + u + v)];
                byte signBit = (byte) ((coeff >> 15) & 1);
                x |= (byte) (signBit << v);
            }

            sig[(short) (bufOffset + (u >> 3))] = x;
        }

        bufOffset += (short) (n >> 3);
        remainingLen -= (short) (n >> 3);

        // 3. Fixed-size low bits; reimplemented without long.
        short lowMask = (short) ((1 << low) - 1);

        int acc8 = 0; // using int for accumulation to avoid long arithmetic
        short accBits = 0;

        for (u = 0; u < n; u++) {

            short w = s1[(short) (s1Offset + u)];
            short mask = tbmask(w);
            w ^= mask; // abs(w)
            acc8 |= (w & lowMask) << accBits;
            accBits += low;

            while (accBits >= 8) {
                if (remainingLen <= 0) {
                    return false;
                }
                sig[bufOffset++] = (byte) (acc8 & 0xFF);
                acc8 >>>= 8;
                accBits -= 8;
                remainingLen--;
            }
        }

        // 4. Variable-size unary encoding
        int acc = 0;
        short accLen = 0;

        for (u = 0; u < n; u++) {

            short w = s1[(short) (s1Offset + u)];
            short mask = tbmask(w);

            w ^= mask;

            short k = (short) (w >>> low);

            acc |= (1 << (accLen + k));
            accLen += (short) (1 + k);

            while (accLen >= 8) {
                if (remainingLen <= 0) {
                    return false;
                }
                sig[bufOffset++] = (byte) acc;
                remainingLen--;
                acc >>>= 8;
                accLen -= 8;
            }
        }

        // Flush remaining bits
        if (accLen > 0) {
            if (remainingLen <= 0) {
                return false;
            }
            sig[bufOffset++] = (byte) acc;
            remainingLen--;
        }

        // 5. Zero padding
        Util.arrayFillNonAtomic(sig, bufOffset, remainingLen, (byte) 0);
        return true;
    }

    /**
     * Sign method
     */
    public short sign(short logn, short useShake, byte[] sig, SHAKE256JC shake256jc, byte[] priv, short privLen, byte[] tmp, short tmpLen) {
        // Ensure proper alignment for 64-bit access
        if (tmpLen < 7) {
            return 0;
        }
        if (logn < 8 || logn > 10) {
            return 0;
        }

        // Align temporary buffer for 64-bit access
        int utmp1 = 0;
        int utmp2 = (utmp1 + 7) & ~7;
        tmpLen -= (int) (utmp2 - utmp1);

        // short minTmpLen = (short) (6 << logn);
        short minTmpLen = 512;
        if (tmpLen < minTmpLen) {
            return 0;
        }

        short seedLen = 24;
        short hpubLen = 32;

        // Memory layout in tmp buffer
        byte[] g = new byte[n];
        byte[] ww = new byte[(short) (2 * n)];
        byte[] x0 = new byte[(short) (2 * n)];
        byte[] f = new byte[n];

        // Re-expand the private key
        byte[] F2, G2;
        byte[] hpub;

        // Regenerate f and g from seed // DecodePrivate(priv) & Regeneratefg(kgseed)
        byte[] seed = new byte[seedLen];
        Util.arrayCopy(priv, (short) 0, seed, (short) 0, (short) seedLen);
        regen_fg(f, (short) 0, g, (short) 0, seed);
        Util.arrayCopy(seed, (short) 0, tmp, (short) 0, (short) seedLen);
        F2 = new byte[n >> 3];
        G2 = new byte[n >> 3];
        hpub = new byte[hpubLen];
        Util.arrayCopy(priv, (short) seedLen, F2, (short) 0, (short) (n >> 3));
        Util.arrayCopy(priv, (short) (seedLen + (n >> 3)), G2, (short) 0, (short) (n >> 3));
        Util.arrayCopy(priv, (short) (seedLen + 2 * (n >> 3)), hpub, (short) 0, (short) hpubLen);

        // Compute hm = SHAKE256(message || hpub)
        byte[] hm = new byte[64];
        shake256jc.update(hpub, (short) 0, (short) hpubLen);
        shake256jc.doFinal(hm, (short) 0, (short) hm.length);

        // Main signing loop
        for (short attempt = 0;; attempt += 2) {
            int t0Offset = 0;
            int t1Offset = t0Offset + (n >> 3);
            int h0Offset = t1Offset + (n >> 3);
            int h1Offset = h0Offset + (n >> 3);
            int f2Offset = h1Offset + (n >> 3);
            int g2Offset = f2Offset + (n >> 3);
            int xxOffset = g2Offset + (n >> 3);

            // Generate salt
            byte[] salt = new byte[saltLen];
            random.generateData(salt, (short) 0, (short) saltLen);

            if (useShake != 0) {
                byte[] tbuf = new byte[4];
                enc32le(tbuf, (short)0, (short)(attempt >>> 16), (short)attempt);

                SHAKE256JC saltShake = new SHAKE256JC();
                saltShake.update(hm, (short) 0, (short) hm.length);
                saltShake.update(priv, (short) 0, (short) seedLen); // problem?
                saltShake.update(tbuf, (short) 0, (short) tbuf.length);
                saltShake.update(salt, (short) 0, (short) saltLen);
                saltShake.doFinal(salt, (short) 0, saltLen);
            }

            // Compute h = SHAKE256(hm || salt)
            SHAKE256JC hShake = new SHAKE256JC();
            hShake.update(hm, (short) 0, (short) hm.length);
            hShake.update(salt, (short) 0, (short) saltLen);

            // Squeeze h0 and h1 (total n >> 2 bytes)
            hShake.doFinal(ww, (short) h0Offset, (short) (n >> 2));

            // Extract low bits and compute t = B*h (mod 2)
            byte[] f2 = new byte[n >> 3];
            byte[] g2 = new byte[n >> 3];
            extract_lowbit(logn, f2, f);
            extract_lowbit(logn, g2, g);

            basisM2Mul(logn,
                ww, (short)t0Offset,
                ww, (short)t1Offset,
                ww, (short)h0Offset,
                ww, (short)h1Offset,
                f2, (short)0,
                g2, (short)0,
                F2, (short)0,
                G2, (short)0,
                tmp, (short)xxOffset);
            // Sample x using Gaussian distribution
            short xsn;
            byte[] tbuf = new byte[4];
            int att1 = attempt + 1;
            enc32le(tbuf, (short)0, (short)(att1 >>> 16), (short)att1);

            SHAKE256JC gaussShake = new SHAKE256JC();

            gaussShake.update(hm, (short) 0, (short) hm.length);
            gaussShake.update(priv, (short) 0, (short) seedLen); 
            gaussShake.update(tbuf, (short) 0, (short) tbuf.length);

            xsn = sigGauss(logn, gaussShake, x0, (short) 0, ww, (short) t0Offset);

            // Reject if squared norm is too large
            if (xsn > maxXnorm) {
                continue;
            }

            // Compute s1 = f*x1 - g*x0 using NTT over Q=18433
            short[] w1 = new short[n];
            short[] w2 = new short[n];
            short[] w3 = new short[n];

            // w1 <- g*x0 in NTT domain
            mq18433PolySetSmall(logn, w1, (short) 0, g, (short) 0);
            mq18433PolySetSmall(logn, w2, (short) 0, x0, (short) 0);
            mq18433NTT(logn, w1, (short)0);
            mq18433NTT(logn, w2, (short)0);
            for (short u = 0; u < n; u++) {
                w1[u] = mq18433MontyMul((short) (w1[u]), (short) (w2[u]));
            }

            // w3 <- f*x1 - g*x0, then INTT to get polynomial
            mq18433PolySetSmall(logn, w2, (short) 0, x0, n); // x1 = x0[n..2n-1]
            mq18433PolySetSmall(logn, w3, (short) 0, f, (short)0);
            mq18433NTT(logn, w2, (short) 0);
            mq18433NTT(logn, w3, (short) 0);
            for (short u = 0; u < n; u++) {
                w3[u] = mq18433ToMonty(mq18433Sub(mq18433MontyMul(w2[u], w3[u]), w1[u]));
            }
            mq18433INTT(logn, w3, (short) 0);
            mq18433PolySnorm(logn, w3, (short)0);

            short[] s1 = w3;

            int ps = polySymBreak(logn, s1, (short) 0);
            int lim = 1 << ((logn == 10) ? 10 : 9);
            short nm = (short) ~tbmask((short) (ps - 1));

            byte[] h1buf = new byte[n >> 3];
            Util.arrayCopy(ww, (short) h1Offset, h1buf, (short) 0, (short) (n >> 3));

            // Per-coefficient bounds check
            int reject = 0;
            for (short u = 0; u < n; u++) {
                int z = s1[u];
                z = ((z ^ nm) - nm) + ((h1buf[u >> 3] >> (u & 7)) & 1);
                int y = z >> 1;

                // -1 if y < -lim or y >= lim, 0 otherwise
                short negLim = (short)-lim;

                short outOfRange = 0;

                if ((short)y < negLim || (short)y >= (short)lim) {
                    outOfRange = (short)-1;
                }
                reject |= outOfRange;
                s1[u] = (short) y;
            }

            if (reject != 0) {
                continue;
            }

            // Encode signature
            short sigLen = HAWK_SIG_SIZE(logn);
            if (encodeSig(logn, tmp, (short) 0, sigLen, salt, (short) 0, saltLen, s1, (short) 0)) {
                if (sig != null) {
                    Util.arrayCopy(tmp, (short) 0, sig, (short) 0, sigLen);
                }
                return 1;
            }
        }
    }

    public short signMessage(short logn, byte[] sig, byte[] message, short messageLen, byte[] priv, short privLen, byte[] tmp, short tmpLen) {
        SHAKE256JC sc = new SHAKE256JC();
        sc.update(message, (short) 0, (short) messageLen);

        // Equivalent of hawkSignFinish
        return sign(logn, (short) 1, sig, sc, priv, privLen, tmp, tmpLen);
    }
}
