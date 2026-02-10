'use client'

import { useState } from 'react'
import { ChevronDown, Globe } from 'lucide-react'
import { Toggle } from '@/components/ui'
import type { Project } from '@prisma/client'
import styles from '../ProjectForm.module.css'
import { TimeEstimate } from '../TimeEstimate'

type FormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

interface HttpxSectionProps {
  data: FormData
  updateField: <K extends keyof FormData>(field: K, value: FormData[K]) => void
}

export function HttpxSection({ data, updateField }: HttpxSectionProps) {
  const [isOpen, setIsOpen] = useState(true)

  return (
    <div className={styles.section}>
      <div className={styles.sectionHeader} onClick={() => setIsOpen(!isOpen)}>
        <h2 className={styles.sectionTitle}>
          <Globe size={16} />
          httpx HTTP Probing
        </h2>
        <ChevronDown
          size={16}
          className={`${styles.sectionIcon} ${isOpen ? styles.sectionIconOpen : ''}`}
        />
      </div>

      {isOpen && (
        <div className={styles.sectionContent}>
          <p className={styles.sectionDescription}>
            HTTP probing and fingerprinting using httpx. Validates live web services, extracts metadata like server headers, technologies, and TLS certificates. Integrates Wappalyzer for comprehensive technology detection.
          </p>
          <div className={styles.fieldRow}>
            <div className={styles.fieldGroup}>
              <label className={styles.fieldLabel}>Threads</label>
              <input
                type="number"
                className="textInput"
                value={data.httpxThreads}
                onChange={(e) => updateField('httpxThreads', parseInt(e.target.value) || 50)}
                min={1}
                max={200}
              />
              <span className={styles.fieldHint}>Concurrent HTTP probing threads</span>
            </div>
            <div className={styles.fieldGroup}>
              <label className={styles.fieldLabel}>Timeout (seconds)</label>
              <input
                type="number"
                className="textInput"
                value={data.httpxTimeout}
                onChange={(e) => updateField('httpxTimeout', parseInt(e.target.value) || 10)}
                min={1}
              />
              <span className={styles.fieldHint}>Request timeout per URL</span>
            </div>
          </div>

          <div className={styles.fieldRow}>
            <div className={styles.fieldGroup}>
              <label className={styles.fieldLabel}>Rate Limit</label>
              <input
                type="number"
                className="textInput"
                value={data.httpxRateLimit}
                onChange={(e) => updateField('httpxRateLimit', parseInt(e.target.value) || 50)}
                min={1}
              />
              <span className={styles.fieldHint}>Requests/sec. Lower (10-50) avoids WAF detection</span>
            </div>
            <div className={styles.fieldGroup}>
              <label className={styles.fieldLabel}>Retries</label>
              <input
                type="number"
                className="textInput"
                value={data.httpxRetries}
                onChange={(e) => updateField('httpxRetries', parseInt(e.target.value) || 2)}
                min={0}
                max={10}
              />
              <span className={styles.fieldHint}>Retry attempts for failed requests</span>
            </div>
          </div>

          <div className={styles.subSection}>
            <h3 className={styles.subSectionTitle}>Redirects</h3>
            <div className={styles.toggleRow}>
              <div>
                <span className={styles.toggleLabel}>Follow Redirects</span>
                <p className={styles.toggleDescription}>Follow 301/302/307 redirects to final destination</p>
              </div>
              <Toggle
                checked={data.httpxFollowRedirects}
                onChange={(checked) => updateField('httpxFollowRedirects', checked)}
              />
            </div>
            {data.httpxFollowRedirects && (
              <div className={styles.fieldGroup}>
                <label className={styles.fieldLabel}>Max Redirects</label>
                <input
                  type="number"
                  className="textInput"
                  value={data.httpxMaxRedirects}
                  onChange={(e) => updateField('httpxMaxRedirects', parseInt(e.target.value) || 10)}
                  min={1}
                  max={50}
                />
                <span className={styles.fieldHint}>Maximum redirect chain depth to prevent loops</span>
              </div>
            )}
          </div>

          <div className={styles.subSection}>
            <h3 className={styles.subSectionTitle}>Response Probe Options</h3>
            <p className={styles.fieldHint} style={{ marginBottom: '0.5rem' }}>Extract data from HTTP responses for analysis</p>
            <div className={styles.toggleRow}>
              <div>
                <span className={styles.toggleLabel}>Status Code</span>
                <p className={styles.toggleDescription}>HTTP status (200, 404, 500, etc.)</p>
              </div>
              <Toggle
                checked={data.httpxProbeStatusCode}
                onChange={(checked) => updateField('httpxProbeStatusCode', checked)}
              />
            </div>
            <div className={styles.toggleRow}>
              <div>
                <span className={styles.toggleLabel}>Content Length</span>
                <p className={styles.toggleDescription}>Response body size in bytes</p>
              </div>
              <Toggle
                checked={data.httpxProbeContentLength}
                onChange={(checked) => updateField('httpxProbeContentLength', checked)}
              />
            </div>
            <div className={styles.toggleRow}>
              <div>
                <span className={styles.toggleLabel}>Content Type</span>
                <p className={styles.toggleDescription}>MIME type (text/html, application/json, etc.)</p>
              </div>
              <Toggle
                checked={data.httpxProbeContentType}
                onChange={(checked) => updateField('httpxProbeContentType', checked)}
              />
            </div>
            <div className={styles.toggleRow}>
              <div>
                <span className={styles.toggleLabel}>Page Title</span>
                <p className={styles.toggleDescription}>HTML title tag content</p>
              </div>
              <Toggle
                checked={data.httpxProbeTitle}
                onChange={(checked) => updateField('httpxProbeTitle', checked)}
              />
            </div>
            <div className={styles.toggleRow}>
              <div>
                <span className={styles.toggleLabel}>Server Header</span>
                <p className={styles.toggleDescription}>Web server software (nginx, Apache, IIS, etc.)</p>
              </div>
              <Toggle
                checked={data.httpxProbeServer}
                onChange={(checked) => updateField('httpxProbeServer', checked)}
              />
            </div>
            <div className={styles.toggleRow}>
              <div>
                <span className={styles.toggleLabel}>Response Time</span>
                <p className={styles.toggleDescription}>Server response latency in milliseconds</p>
              </div>
              <Toggle
                checked={data.httpxProbeResponseTime}
                onChange={(checked) => updateField('httpxProbeResponseTime', checked)}
              />
            </div>
            <div className={styles.toggleRow}>
              <div>
                <span className={styles.toggleLabel}>Word Count</span>
                <p className={styles.toggleDescription}>Number of words in response body</p>
              </div>
              <Toggle
                checked={data.httpxProbeWordCount}
                onChange={(checked) => updateField('httpxProbeWordCount', checked)}
              />
            </div>
            <div className={styles.toggleRow}>
              <div>
                <span className={styles.toggleLabel}>Line Count</span>
                <p className={styles.toggleDescription}>Number of lines in response body</p>
              </div>
              <Toggle
                checked={data.httpxProbeLineCount}
                onChange={(checked) => updateField('httpxProbeLineCount', checked)}
              />
            </div>
            <div className={styles.toggleRow}>
              <div>
                <span className={styles.toggleLabel}>Technology Detection</span>
                <p className={styles.toggleDescription}>Detect frameworks, CMS, and libraries (Wappalyzer-based)</p>
                <TimeEstimate estimate="+10-30% probing time" />
              </div>
              <Toggle
                checked={data.httpxProbeTechDetect}
                onChange={(checked) => updateField('httpxProbeTechDetect', checked)}
              />
            </div>
          </div>

          <div className={styles.subSection}>
            <h3 className={styles.subSectionTitle}>Network Information</h3>
            <div className={styles.toggleRow}>
              <div>
                <span className={styles.toggleLabel}>IP Address</span>
                <p className={styles.toggleDescription}>Resolved IPv4/IPv6 address</p>
              </div>
              <Toggle
                checked={data.httpxProbeIp}
                onChange={(checked) => updateField('httpxProbeIp', checked)}
              />
            </div>
            <div className={styles.toggleRow}>
              <div>
                <span className={styles.toggleLabel}>CNAME Records</span>
                <p className={styles.toggleDescription}>DNS canonical name aliases (reveals CDN/hosting)</p>
              </div>
              <Toggle
                checked={data.httpxProbeCname}
                onChange={(checked) => updateField('httpxProbeCname', checked)}
              />
            </div>
            <div className={styles.toggleRow}>
              <div>
                <span className={styles.toggleLabel}>ASN Information</span>
                <p className={styles.toggleDescription}>Autonomous System Number and network owner</p>
              </div>
              <Toggle
                checked={data.httpxProbeAsn}
                onChange={(checked) => updateField('httpxProbeAsn', checked)}
              />
            </div>
            <div className={styles.toggleRow}>
              <div>
                <span className={styles.toggleLabel}>CDN Detection</span>
                <p className={styles.toggleDescription}>Identify CDN provider (Cloudflare, Akamai, AWS CloudFront)</p>
              </div>
              <Toggle
                checked={data.httpxProbeCdn}
                onChange={(checked) => updateField('httpxProbeCdn', checked)}
              />
            </div>
          </div>

          <div className={styles.subSection}>
            <h3 className={styles.subSectionTitle}>TLS/SSL Information</h3>
            <div className={styles.toggleRow}>
              <div>
                <span className={styles.toggleLabel}>TLS Information</span>
                <p className={styles.toggleDescription}>Certificate issuer, expiry, and cipher suite details</p>
              </div>
              <Toggle
                checked={data.httpxProbeTlsInfo}
                onChange={(checked) => updateField('httpxProbeTlsInfo', checked)}
              />
            </div>
            <div className={styles.toggleRow}>
              <div>
                <span className={styles.toggleLabel}>TLS Certificate Grab</span>
                <p className={styles.toggleDescription}>Extract full certificate data including SANs and chain</p>
              </div>
              <Toggle
                checked={data.httpxProbeTlsGrab}
                onChange={(checked) => updateField('httpxProbeTlsGrab', checked)}
              />
            </div>
          </div>

          <div className={styles.subSection}>
            <h3 className={styles.subSectionTitle}>Fingerprinting</h3>
            <p className={styles.fieldHint} style={{ marginBottom: '0.5rem' }}>Unique identifiers for matching similar servers/services</p>
            <div className={styles.toggleRow}>
              <div>
                <span className={styles.toggleLabel}>Favicon Hash</span>
                <p className={styles.toggleDescription}>MMH3 hash for Shodan/Censys correlation</p>
              </div>
              <Toggle
                checked={data.httpxProbeFavicon}
                onChange={(checked) => updateField('httpxProbeFavicon', checked)}
              />
            </div>
            <div className={styles.toggleRow}>
              <div>
                <span className={styles.toggleLabel}>JARM Fingerprint</span>
                <p className={styles.toggleDescription}>TLS server fingerprint for C2/malware detection</p>
                <TimeEstimate estimate="+10-50 ms per URL (adds up with many hosts)" />
              </div>
              <Toggle
                checked={data.httpxProbeJarm}
                onChange={(checked) => updateField('httpxProbeJarm', checked)}
              />
            </div>
            <div className={styles.fieldGroup}>
              <label className={styles.fieldLabel}>Response Hash Algorithm</label>
              <select
                className="select"
                value={data.httpxProbeHash}
                onChange={(e) => updateField('httpxProbeHash', e.target.value)}
              >
                <option value="sha256">SHA-256</option>
                <option value="md5">MD5</option>
                <option value="sha1">SHA-1</option>
                <option value="sha512">SHA-512</option>
              </select>
              <span className={styles.fieldHint}>Hash algorithm for response body fingerprinting</span>
            </div>
          </div>

          <div className={styles.subSection}>
            <h3 className={styles.subSectionTitle}>Response Data</h3>
            <div className={styles.toggleRow}>
              <div>
                <span className={styles.toggleLabel}>Include Response Body</span>
                <p className={styles.toggleDescription}>Store full HTML/JSON body. Required for Wappalyzer. Increases output size</p>
              </div>
              <Toggle
                checked={data.httpxIncludeResponse}
                onChange={(checked) => updateField('httpxIncludeResponse', checked)}
              />
            </div>
            <div className={styles.toggleRow}>
              <div>
                <span className={styles.toggleLabel}>Include Response Headers</span>
                <p className={styles.toggleDescription}>Store all headers for security header analysis</p>
              </div>
              <Toggle
                checked={data.httpxIncludeResponseHeaders}
                onChange={(checked) => updateField('httpxIncludeResponseHeaders', checked)}
              />
            </div>
          </div>

          <div className={styles.subSection}>
            <h3 className={styles.subSectionTitle}>Custom Paths & Headers</h3>
            <div className={styles.fieldGroup}>
              <label className={styles.fieldLabel}>Additional Paths to Probe</label>
              <textarea
                className="textarea"
                value={data.httpxPaths.join('\n')}
                onChange={(e) => updateField('httpxPaths', e.target.value.split('\n').filter(Boolean))}
                placeholder="/robots.txt&#10;/.well-known/security.txt&#10;/sitemap.xml"
                rows={3}
              />
              <span className={styles.fieldHint}>Probe these paths on each host (in addition to root)</span>
            </div>
            <div className={styles.fieldGroup}>
              <label className={styles.fieldLabel}>Custom Headers</label>
              <textarea
                className="textarea"
                value={data.httpxCustomHeaders.join('\n')}
                onChange={(e) => updateField('httpxCustomHeaders', e.target.value.split('\n').filter(Boolean))}
                placeholder="User-Agent: CustomAgent/1.0&#10;Authorization: Bearer token"
                rows={3}
              />
              <span className={styles.fieldHint}>Browser-like headers help avoid WAF/bot detection</span>
            </div>
          </div>

          <div className={styles.subSection}>
            <h3 className={styles.subSectionTitle}>Status Code Filters</h3>
            <div className={styles.fieldGroup}>
              <label className={styles.fieldLabel}>Match Status Codes</label>
              <input
                type="text"
                className="textInput"
                value={data.httpxMatchCodes.join(', ')}
                onChange={(e) => updateField('httpxMatchCodes', e.target.value.split(',').map(s => s.trim()).filter(Boolean))}
                placeholder="200, 301, 302 (empty = all)"
              />
              <span className={styles.fieldHint}>Whitelist: only include hosts returning these codes</span>
            </div>
            <div className={styles.fieldGroup}>
              <label className={styles.fieldLabel}>Filter Status Codes</label>
              <input
                type="text"
                className="textInput"
                value={data.httpxFilterCodes.join(', ')}
                onChange={(e) => updateField('httpxFilterCodes', e.target.value.split(',').map(s => s.trim()).filter(Boolean))}
                placeholder="404, 503"
              />
              <span className={styles.fieldHint}>Blacklist: exclude hosts returning these codes</span>
            </div>
          </div>

          <div className={styles.subSection}>
            <h3 className={styles.subSectionTitle}>Wappalyzer Technology Detection</h3>
            <div className={styles.toggleRow}>
              <div>
                <span className={styles.toggleLabel}>Enable Wappalyzer</span>
                <p className={styles.toggleDescription}>Detect CMS plugins, analytics, security tools, and frameworks from HTML</p>
                <TimeEstimate estimate="+30-50% probing time" />
              </div>
              <Toggle
                checked={data.wappalyzerEnabled}
                onChange={(checked) => updateField('wappalyzerEnabled', checked)}
              />
            </div>
            {data.wappalyzerEnabled && (
              <>
                <div className={styles.fieldRow}>
                  <div className={styles.fieldGroup}>
                    <label className={styles.fieldLabel}>Min Confidence (%)</label>
                    <input
                      type="number"
                      className="textInput"
                      value={data.wappalyzerMinConfidence}
                      onChange={(e) => updateField('wappalyzerMinConfidence', parseInt(e.target.value) || 50)}
                      min={0}
                      max={100}
                    />
                    <span className={styles.fieldHint}>Lower = more detections, more false positives</span>
                  </div>
                  <div className={styles.fieldGroup}>
                    <label className={styles.fieldLabel}>Cache TTL (hours)</label>
                    <input
                      type="number"
                      className="textInput"
                      value={data.wappalyzerCacheTtlHours}
                      onChange={(e) => updateField('wappalyzerCacheTtlHours', parseInt(e.target.value) || 24)}
                      min={1}
                    />
                    <span className={styles.fieldHint}>How long to cache tech database (0 = always fresh)</span>
                  </div>
                </div>
                <div className={styles.toggleRow}>
                  <div>
                    <span className={styles.toggleLabel}>Require HTML Body</span>
                    <p className={styles.toggleDescription}>Skip non-HTML responses. Recommended for accuracy</p>
                  </div>
                  <Toggle
                    checked={data.wappalyzerRequireHtml}
                    onChange={(checked) => updateField('wappalyzerRequireHtml', checked)}
                  />
                </div>
                <div className={styles.toggleRow}>
                  <div>
                    <span className={styles.toggleLabel}>Auto Update Database</span>
                    <p className={styles.toggleDescription}>Download latest tech signatures from npm (recommended)</p>
                  </div>
                  <Toggle
                    checked={data.wappalyzerAutoUpdate}
                    onChange={(checked) => updateField('wappalyzerAutoUpdate', checked)}
                  />
                </div>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>NPM Version</label>
                  <input
                    type="text"
                    className="textInput"
                    value={data.wappalyzerNpmVersion}
                    disabled
                  />
                  <span className={styles.fieldHint}>Wappalyzer package version for tech database</span>
                </div>
              </>
            )}
          </div>

          <div className={styles.subSection}>
            <h3 className={styles.subSectionTitle}>Banner Grabbing</h3>
            <div className={styles.toggleRow}>
              <div>
                <span className={styles.toggleLabel}>Enable Banner Grabbing</span>
                <p className={styles.toggleDescription}>Detect service versions on non-HTTP ports (SSH, FTP, MySQL, SMTP)</p>
              </div>
              <Toggle
                checked={data.bannerGrabEnabled}
                onChange={(checked) => updateField('bannerGrabEnabled', checked)}
              />
            </div>
            {data.bannerGrabEnabled && (
              <div className={styles.fieldRow}>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Timeout (seconds)</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.bannerGrabTimeout}
                    onChange={(e) => updateField('bannerGrabTimeout', parseInt(e.target.value) || 5)}
                    min={1}
                  />
                  <span className={styles.fieldHint}>Connection timeout per port</span>
                </div>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Threads</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.bannerGrabThreads}
                    onChange={(e) => updateField('bannerGrabThreads', parseInt(e.target.value) || 20)}
                    min={1}
                  />
                  <span className={styles.fieldHint}>Concurrent banner grab threads</span>
                </div>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Max Banner Length</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.bannerGrabMaxLength}
                    onChange={(e) => updateField('bannerGrabMaxLength', parseInt(e.target.value) || 500)}
                    min={100}
                    max={5000}
                  />
                  <span className={styles.fieldHint}>Truncate banners longer than this (chars)</span>
                </div>
              </div>
            )}
          </div>

          <div className={styles.fieldGroup}>
            <label className={styles.fieldLabel}>Docker Image</label>
            <input
              type="text"
              className="textInput"
              value={data.httpxDockerImage}
              disabled
            />
          </div>
        </div>
      )}
    </div>
  )
}
