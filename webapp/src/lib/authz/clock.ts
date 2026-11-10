/**
 * The authorization core's only source of time (DV-12). It is the plugin
 * platform's clock, not a copy, so one `setNowForTests` pins every expiry and
 * lifetime check in both, and a test can never see the two disagree.
 */
export { now, setNowForTests } from '@/lib/plugins/clock'
