/**
 \file 		threshold-euclidean-dist.cpp
 \author	lukas_christof.scheidel@stud.tu-darmstadt.de
 \copyright	ABY - A Framework for Efficient Mixed-protocol Secure Two-party Computation
			Copyright (C) 2021 Engineering Cryptographic Protocols Group, TU Darmstadt
			This program is free software: you can redistribute it and/or modify
            it under the terms of the GNU Lesser General Public License as published
            by the Free Software Foundation, either version 3 of the License, or
            (at your option) any later version.
            ABY is distributed in the hope that it will be useful,
            but WITHOUT ANY WARRANTY; without even the implied warranty of
            MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
            GNU Lesser General Public License for more details.
            You should have received a copy of the GNU Lesser General Public License
            along with this program. If not, see <http://www.gnu.org/licenses/>.
 \brief		2D SIMD Threshold Euclidean distance Test class implementation.
 *              Implements the functionality from PST’15 (http://ieeexplore.ieee.org/document/7232947/).
 */
#include "three_halves.h"
#include "../../../abycore/circuit/booleancircuits.h"
#include "../../../abycore/sharing/sharing.h"
#include <ENCRYPTO_utils/crypto/crypto.h>
#include <random>

int32_t test_three_halves_circuit(e_role role, const std::string& address, uint16_t port, seclvl seclvl, uint32_t operationbitlen,
                                  uint32_t nthreads, e_mt_gen_alg mt_alg, e_sharing dstsharing, e_sharing minsharing, uint32_t n, bool only_yao) {

    ABYParty* party = new ABYParty(role, address, port, seclvl, operationbitlen, nthreads, mt_alg);
    std::vector<Sharing*>& sharings = party->GetSharings();

    const uint32_t nvals = 1;


    uint8_t x1[nvals];
    uint8_t x2[nvals];
    uint8_t y1[nvals];
    uint8_t y2[nvals];

    srand(1236614242);

    for(uint32_t i = 0; i < nvals; ++i) {
        x1[i] = (uint8_t) (rand() % 256);
        y1[i] = (uint8_t) (rand() % 256);
        y2[i] = (uint8_t) (rand() % 256);;
        x2[i] = (uint8_t) (rand() % 256);;
    }

    for (int i = 0; i < nvals; i++) {
        std::cout << "x1: " << (int) x1[i] << ", y1: " << (int) y1[i] << "; x2: " << (int) x2[i] << ", y2: "
                  << (int) y2[i] << std::endl;
    }

    Circuit *yaocirc;

    share *s_x1, *s_x2, *s_y1, *s_y2;

    yaocirc = sharings[minsharing]->GetCircuitBuildRoutine();

    if (role == SERVER) {
        s_x1 = yaocirc->PutSIMDINGate(nvals, x1, operationbitlen, SERVER);
        s_y1 = yaocirc->PutSIMDINGate(nvals, y1, operationbitlen, SERVER);
        s_x2 = yaocirc->PutDummySIMDINGate(nvals, operationbitlen);
        s_y2 = yaocirc->PutDummySIMDINGate(nvals, operationbitlen);
    } else {
        s_x1 = yaocirc->PutDummySIMDINGate(nvals, operationbitlen);
        s_y1 = yaocirc->PutDummySIMDINGate(nvals, operationbitlen);
        s_x2 = yaocirc->PutSIMDINGate(nvals, x2, operationbitlen, CLIENT);
        s_y2 = yaocirc->PutSIMDINGate(nvals, y2, operationbitlen, CLIENT);
    }

    std::vector<share*> dst = build_three_halves_circuit(s_x1, s_y1, s_x2, s_y2,
                                                         operationbitlen, (BooleanCircuit*) yaocirc, only_yao);

    share* out1, *out2, *out3;

    /** MILLIONAIRES PROBLEM**/
    out1 = yaocirc->PutOUTGate(dst[0], ALL);

    /** THREE HALVES TEST **/
    /*out1 = yaocirc->PutOUTGate(dst[0], ALL);
    out2 = yaocirc->PutOUTGate(dst[1], ALL);
    out3 = yaocirc->PutOUTGate(dst[2], ALL);*/

    printf("Executing Circuit\n");
    party->ExecCircuit();
    printf("Executing Circuit\n");

    uint32_t *output;
    uint32_t out_bitlen, out_nvals;

    uint32_t *output1;
    uint32_t out_bitlen1, out_nvals1;

    uint32_t *output2;
    uint32_t out_bitlen2, out_nvals2;

    if(role == CLIENT) {

        /** THREE HALVES TEST **/
        out1->get_clear_value_vec(&output, &out_bitlen, &out_nvals);
        for (int i = 0; i < out_nvals; i++) {
            std::cout << "x1: " << (int) x1[i] << ", y1: " << (int) y1[i] << "; x2: " << (int) x2[i] << ", y2: "
                      << (int) y2[i] << std::endl;

            std::cout << "Circuit result: " << output[i];

            std::cout << " Verification: " << /*((*/(x1[i] & x2[i]) /*& y2[i]) ^ ((y1[i] ^ y2[i]) & x2[i]))*/ << std::endl;
        }

    }else if(role == SERVER) {

        /** THREE HALVES TEST **/
        out1->get_clear_value_vec(&output, &out_bitlen, &out_nvals);
        for (int i = 0; i < out_nvals; i++) {
            std::cout << "x1: " << (int) x1[i] << ", y1: " << (int) y1[i] << "; x2: " << (int) x2[i] << ", y2: "
                      << (int) y2[i] << std::endl;

            std::cout << "Circuit result: " << output[i];

            std::cout << " Verification: " << /*((*/(x1[i] & x2[i]) /*& y2[i]) ^ ((y1[i] ^ y2[i]) & x2[i]))*/ << std::endl;
        }

    }
    return 0;
}

//Build_

std::vector<share*> build_three_halves_circuit(share* x1, share* y1, share* x2, share* y2, uint32_t bitlen,
                                               BooleanCircuit* mincirc,bool only_yao) {

    share* out, *t_a, *t_b, *res_x, *res_y,
            *check_sel, *check_sel_inv;

    /*t_a = mincirc->PutANDGate(x1, x2);
    t_b = mincirc->PutANDGate(y1, y2);
    out = mincirc->PutANDGate(t_a, t_b);

    std::vector<share*> out11 = {t_a, t_b, out};*/


    check_sel = mincirc->PutANDGate(x1, x2);
    /*check_sel = mincirc->PutANDGate(check_sel, y2);
    check_sel_inv = mincirc->PutXORGate(y1, y2);
    check_sel_inv = mincirc->PutANDGate(check_sel_inv, x2);
    out = mincirc->PutXORGate(check_sel, check_sel_inv);*/

    std::vector<share*> out11 = {check_sel};

    return out11;
}