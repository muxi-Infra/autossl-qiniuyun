package cron

import (
	"crypto/x509"
	"testing"
)

func TestCertSubject(t *testing.T) {
	tests := []struct {
		domain  string
		want    string
		wantErr bool
	}{
		// 线上出问题的两个域名：必须落到不同的证书主体上
		{domain: "ota.ccnubox.muxixyz.com", want: "*.ccnubox.muxixyz.com"},
		{domain: "assets.ota.ccnubox.muxixyz.com", want: "*.ota.ccnubox.muxixyz.com"},
		// 存量的三段域名依旧共用一张 *.muxixyz.com
		{domain: "forum.muxixyz.com", want: "*.muxixyz.com"},
		{domain: "static.muxixyz.com", want: "*.muxixyz.com"},
		// 七牛云泛域名以 "." 开头
		{domain: ".muxixyz.com", want: "*.muxixyz.com"},
		// 注册域本身只能签单域名证书
		{domain: "muxixyz.com", want: "muxixyz.com"},
		// 更深的层级不会被压缩到上层
		{domain: "a.b.ota.ccnubox.muxixyz.com", want: "*.b.ota.ccnubox.muxixyz.com"},
		// 多段公共后缀
		{domain: "example.co.uk", want: "example.co.uk"},
		{domain: "www.example.co.uk", want: "*.example.co.uk"},
		// 非法输入
		{domain: "", wantErr: true},
		{domain: ".", wantErr: true},
	}

	for _, tt := range tests {
		got, err := certSubject(tt.domain)
		if tt.wantErr {
			if err == nil {
				t.Errorf("certSubject(%q) 期望报错，实际返回 %q", tt.domain, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("certSubject(%q) 意外报错: %v", tt.domain, err)
			continue
		}
		if got != tt.want {
			t.Errorf("certSubject(%q) = %q, 期望 %q", tt.domain, got, tt.want)
		}
	}
}

func TestCertCovers(t *testing.T) {
	tests := []struct {
		name     string
		dnsNames []string
		domain   string
		want     bool
	}{
		// 线上故障的根因：裸域证书盖不住子域名
		{name: "裸域证书不覆盖子域", dnsNames: []string{"ota.ccnubox.muxixyz.com"}, domain: "assets.ota.ccnubox.muxixyz.com", want: false},
		{name: "裸域证书覆盖自身", dnsNames: []string{"ota.ccnubox.muxixyz.com"}, domain: "ota.ccnubox.muxixyz.com", want: true},
		// 通配符只匹配一级 label，且不匹配父域本身
		{name: "通配符覆盖一级子域", dnsNames: []string{"*.ota.ccnubox.muxixyz.com"}, domain: "assets.ota.ccnubox.muxixyz.com", want: true},
		{name: "通配符不覆盖父域自身", dnsNames: []string{"*.ota.ccnubox.muxixyz.com"}, domain: "ota.ccnubox.muxixyz.com", want: false},
		{name: "通配符不跨级匹配", dnsNames: []string{"*.ccnubox.muxixyz.com"}, domain: "assets.ota.ccnubox.muxixyz.com", want: false},
		{name: "上级通配符覆盖父域", dnsNames: []string{"*.ccnubox.muxixyz.com"}, domain: "ota.ccnubox.muxixyz.com", want: true},
		// 七牛云泛域名
		{name: "泛域名匹配通配符证书", dnsNames: []string{"*.muxixyz.com"}, domain: ".muxixyz.com", want: true},
		{name: "泛域名不匹配裸域证书", dnsNames: []string{"muxixyz.com"}, domain: ".muxixyz.com", want: false},
		// 大小写不敏感
		{name: "大小写不敏感", dnsNames: []string{"*.MuxiXyz.com"}, domain: "Forum.muxixyz.COM", want: true},
		// 多 SAN
		{name: "多SAN命中其一", dnsNames: []string{"muxixyz.com", "*.muxixyz.com"}, domain: "forum.muxixyz.com", want: true},
	}

	for _, tt := range tests {
		cert := &x509.Certificate{DNSNames: tt.dnsNames}
		if got := certCovers(cert, tt.domain); got != tt.want {
			t.Errorf("%s: certCovers(%v, %q) = %v, 期望 %v", tt.name, tt.dnsNames, tt.domain, got, tt.want)
		}
	}
}

// TestCertSubjectAlwaysCoversDomain 核心不变量：
// 按 certSubject 申请出来的证书，一定覆盖得住申请它的那个域名。
// 违反这一点就会重演"证书绑不上、状态却记成功"的线上故障。
func TestCertSubjectAlwaysCoversDomain(t *testing.T) {
	domains := []string{
		"ota.ccnubox.muxixyz.com",
		"assets.ota.ccnubox.muxixyz.com",
		"forum.muxixyz.com",
		".muxixyz.com",
		"muxixyz.com",
		"a.b.ota.ccnubox.muxixyz.com",
		"www.example.co.uk",
		"example.co.uk",
	}

	for _, domain := range domains {
		subject, err := certSubject(domain)
		if err != nil {
			t.Errorf("certSubject(%q) 报错: %v", domain, err)
			continue
		}
		cert := &x509.Certificate{DNSNames: []string{subject}}
		if !certCovers(cert, domain) {
			t.Errorf("证书主体 %q 覆盖不了它自己的域名 %q", subject, domain)
		}
	}
}

func TestCheckIfPass(t *testing.T) {
	const now = 1_000_000_000
	if checkIfPass(now, now+19*SecondsPerDay) {
		t.Error("剩余 19 天应判定为需要续期")
	}
	if !checkIfPass(now, now+21*SecondsPerDay) {
		t.Error("剩余 21 天不应触发续期")
	}
	if checkIfPass(now, 0) {
		t.Error("七牛云返回 0（证书不存在）必须判定为不可用")
	}
}
