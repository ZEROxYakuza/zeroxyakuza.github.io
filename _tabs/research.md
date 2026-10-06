---
layout: page
title: Research
permalink: /research/
---

# Research

A collection of longer-form vulnerability research projects and technical investigations.

<div class="research-grid">
{% for item in site.research %}
  <a class="research-card" href="{{ item.url | relative_url }}">
    <span>{{ item.date | date: "%Y" }}</span>
    <h3>{{ item.title }}</h3>
    <p>{{ item.description }}</p>
  </a>
{% endfor %}
</div>
