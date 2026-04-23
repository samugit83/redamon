import { useState, useEffect } from 'react'

export const LOADING_STATUS_WORDS = [
  'Negotiating with the network...',
  'Asking the bits nicely...',
  'Convincing the server to talk...',
  'Reading between the packets...',
  'Shaking hands with the target...',
  'Befriending the firewall...',
  'Teaching bytes to cooperate...',
  'Untangling the topology...',
  'Letting the data settle...',
  'Whispering to the DNS...',
  'Collecting breadcrumbs...',
  'Following the wire...',
  'Connecting the dots...',
  'Pulling the threads...',
  'Unfolding the map...',
  'Warming up the graph...',
  'Chasing loose ends...',
  'Sorting through the noise...',
  'Peeking around corners...',
  'Sketching the big picture...',
  'Tuning into the signal...',
  'Piecing it together...',
  'Building the puzzle...',
  'Tracing the trail...',
  'Digging a little deeper...',
  'Almost there, probably...',
  'Making friends with the data...',
  'Sifting through the layers...',
  'Listening to the wire...',
  'Mapping the terrain...',
  'Poking around gently...',
  'Sweet-talking the endpoints...',
  'Unwrapping the responses...',
  'Decoding the conversation...',
  'Charming the routers...',
  'Nudging the services...',
  'Flipping through the records...',
  'One packet at a time...',
  'Gathering intel quietly...',
  'Reading the fine print...',
  'Checking under the hood...',
  'Knocking on every door...',
  'Stitching the fragments...',
  'Patience, the graph is cooking...',
  'Herding the results...',
  'Tiptoeing through the stack...',
  'Borrowing some bandwidth...',
  'Persuading the protocols...',
  'Turning over every stone...',
  'Measuring the surface...',
]

function useRotatingWord(words: string[], intervalMs = 2500) {
  const [index, setIndex] = useState(() => Math.floor(Math.random() * words.length))
  useEffect(() => {
    const timer = setInterval(() => {
      setIndex(prev => {
        let next: number
        do {
          next = Math.floor(Math.random() * words.length)
        } while (next === prev && words.length > 1)
        return next
      })
    }, intervalMs)
    return () => clearInterval(timer)
  }, [words.length, intervalMs])
  return words[index]
}

export function useLoadingWord(): string {
  return useRotatingWord(LOADING_STATUS_WORDS)
}
