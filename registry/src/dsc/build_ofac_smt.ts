import * as fs from 'fs';
import { buildSelfricaSMT, buildSMT } from '../../../common/src/utils/trees'

async function build_ofac_smt() {
    let startTime = performance.now();
    const names = JSON.parse(fs.readFileSync("../../../common/ofacdata/inputs/names.json") as unknown as string);

    // -----PASSPORT DATA-----
    const passports = JSON.parse(fs.readFileSync("../../../common/ofacdata/inputs/passports.json") as unknown as string)

    const passportNoAndNationalityTree = buildSMT(passports, "passport_no_and_nationality");
    const nameAndDobPassportTree = buildSMT(names, "name_and_dob");
    const nameAndYobPassportTree = buildSMT(names, "name_and_yob");

    console.log("Total passports numbers and nationalities processed are : ", passportNoAndNationalityTree[0], " over ", passports.length)
    console.log("SMT for passports numbers and nationalities built in" + passportNoAndNationalityTree[1] + "ms")
    console.log("Total names and dob processed are : ", nameAndDobPassportTree[0], " over ", names.length)
    console.log("SMT for names and dob built in " + nameAndDobPassportTree[1] + "ms")
    console.log("Total names and yob processed are : ", nameAndYobPassportTree[0], " over ", names.length)
    console.log("SMT for names and yob built in " + nameAndYobPassportTree[1] + "ms")
    console.log('Total Time : ', performance.now() - startTime, 'ms')

    const passportNoAndNationalityOfacJSON = passportNoAndNationalityTree[2].export()
    const nameAndDobOfacJSON = nameAndDobPassportTree[2].export()
    const nameAndYobOfacJSON = nameAndYobPassportTree[2].export()

    fs.writeFileSync("../../../common/ofacdata/outputs/passportNoAndNationalitySMT.json", JSON.stringify(passportNoAndNationalityOfacJSON));
    fs.writeFileSync("../../../common/ofacdata/outputs/nameAndDobSMT.json", JSON.stringify(nameAndDobOfacJSON));
    fs.writeFileSync("../../../common/ofacdata/outputs/nameAndYobSMT.json", JSON.stringify(nameAndYobOfacJSON));

    // -----SELFRICA DATA-----
    const nameAndDobSelfricaTree = buildSelfricaSMT(names, "name_and_dob");
    const nameAndYobSelfricaTree = buildSelfricaSMT(names, "name_and_yob");

    const nameAndDobSelfricaOfacJSON = nameAndDobSelfricaTree[2].export()
    const nameAndYobSelfricaOfacJSON = nameAndYobSelfricaTree[2].export()

    fs.writeFileSync("../../../common/ofacdata/outputs/nameAndDobSelfricaSMT.json", JSON.stringify(nameAndDobSelfricaOfacJSON));
    fs.writeFileSync("../../../common/ofacdata/outputs/nameAndYobSelfricaSMT.json", JSON.stringify(nameAndYobSelfricaOfacJSON));
}

build_ofac_smt()