// main_test.go —— 单元测试：清分拆分计算、签名口径与防伪验签
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"testing"
)

// TestSplitAmountsConservation 验证默认比例（9200/500/300）拆分后三项之和恒等于总额
func TestSplitAmountsConservation(t *testing.T) {
	rule := SplitRule{Farmer: 9200, Coop: 500, Reserve: 300}
	cases := []int64{1, 33, 100, 12345, 999999, 123456789}
	for _, total := range cases {
		farmer, coop, reserve := splitAmounts(total, rule)
		if farmer+coop+reserve != total {
			t.Fatalf("总额不守恒: total=%d, farmer=%d, coop=%d, reserve=%d", total, farmer, coop, reserve)
		}
	}
}

// TestSplitAmountsDefaultRatio 验证默认比例下农户占 92%
func TestSplitAmountsDefaultRatio(t *testing.T) {
	rule := SplitRule{Farmer: 9200, Coop: 500, Reserve: 300}
	total := int64(1000000) // 10000.00 元
	farmer, coop, reserve := splitAmounts(total, rule)
	if farmer != 920000 || coop != 50000 || reserve != 30000 {
		t.Fatalf("默认比例拆分错误: farmer=%d, coop=%d, reserve=%d", farmer, coop, reserve)
	}
}

// TestCanonicalReport 验证签名口径的确定性与区分度（任意字段变化都应改变摘要）
func TestCanonicalReport(t *testing.T) {
	qr := QualityReport{
		BatchID: "YC202610070001", FarmerID: "farmer_0x9f",
		Grade: "A", WeightKg: 125.500, UnitPrice: 42.00,
	}
	s1 := canonicalReport(qr)
	s2 := canonicalReport(qr)
	if s1 != s2 {
		t.Fatalf("签名口径不确定: %q vs %q", s1, s2)
	}
	if h1, h2 := sha256.Sum256([]byte(s1)), sha256.Sum256([]byte(canonicalReport(
		QualityReport{BatchID: "YC202610070002", FarmerID: "farmer_0x9f",
			Grade: "A", WeightKg: 125.500, UnitPrice: 42.00}))); h1 == h2 {
		t.Fatalf("不同批次的报告摘要不应相同")
	}
}

// TestVerifyReportSignature 验证 ECDSA 报告签名校验：正确签名通过，篡改后失败
func TestVerifyReportSignature(t *testing.T) {
	// 1) 生成检测机构密钥对（演示用 P-256）
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))

	qr := QualityReport{
		BatchID: "YC202610070001", FarmerID: "farmer_0x9f",
		Grade: "A", WeightKg: 125.500, UnitPrice: 42.00,
	}

	// 2) 检测机构对报告规范化串签名（与合约验签口径一致）
	digest := sha256.Sum256([]byte(canonicalReport(qr)))
	sig, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	qr.Signature = base64.StdEncoding.EncodeToString(sig)

	// 3) 正确签名应通过校验
	if !verifyReportSignature(pubPEM, qr) {
		t.Fatal("合法签名校验失败")
	}

	// 4) 篡改过磅重量后原签名应校验失败（防伪）
	tampered := qr
	tampered.WeightKg = 999.999
	if verifyReportSignature(pubPEM, tampered) {
		t.Fatal("篡改后的报告仍通过校验，存在防伪漏洞")
	}
}
